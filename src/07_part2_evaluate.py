"""Part 2: compare what the stream produced with the batch truth and with OSV."""
import glob
import json

import pandas as pd
from pyspark.sql import functions as F

from common import get_spark, save_csv
from config import DATA, GOLD, RESULTS, SILVER

OUT = "part2/"
STREAM = DATA / "stream"
MAX_DELAY_H = 48       # the longest simulated delay, see 05_part2_prepare.py


def has_data(path):
    return bool(glob.glob(str(path / "*.parquet")))


def completeness(spark, sink, truth, label, first=None, last=None):
    """Closed windows vs the same hours in batch. Only hours whose events have all arrived are compared,
    so the gap is exactly what the watermark threw away."""
    got = spark.read.parquet(str(sink)).groupBy("window_start", "action_type").agg(F.sum("count").alias("stream_count"))
    bounds = got.agg(F.min("window_start").alias("a"), F.max("window_start").alias("b")).first()
    # Without a known slice, use the windows emitted, less the longest delay at either end.
    lo = pd.Timestamp(first, unit="s") if first else pd.Timestamp(bounds["a"]) + pd.Timedelta(hours=MAX_DELAY_H)
    hi = pd.Timestamp(last, unit="s") - pd.Timedelta(hours=MAX_DELAY_H + 1) if last else pd.Timestamp(bounds["b"]) - pd.Timedelta(hours=MAX_DELAY_H)
    t = truth.filter((F.col("hour") >= str(lo)) & (F.col("hour") <= str(hi)))
    joined = t.join(got, (t.hour == got.window_start) & (t.action_type == got.action_type), "left")
    row = joined.agg(F.sum("count").alias("truth"), F.sum(F.coalesce("stream_count", F.lit(0))).alias("stream")).first()
    return {"run": label, "hours_from": str(lo), "hours_to": str(hi), "window_rows": joined.count(),
            "truth_events": row["truth"], "stream_events": row["stream"], "lost_events": row["truth"] - row["stream"],
            "pct_complete": round(100 * row["stream"] / row["truth"], 4),
            "window_rows_missing": joined.filter(F.col("stream_count").isNull()).count(),
            "window_rows_above_truth": joined.filter(F.col("stream_count") > F.col("count")).count()}


def evaluate_short_lived(spark):
    alerts = spark.read.parquet(str(STREAM / "sink_replay" / "short_lived")).dropDuplicates(["name_norm", "created_ts"])
    mal = spark.read.parquet(str(SILVER / "flaw_package")).filter("is_malicious").select(F.col("package").alias("name_norm")).distinct()
    # A quarantine later lifted was a false alarm, whatever the advisory data says.
    cleared = (spark.read.parquet(str(SILVER / "events")).filter(F.col("action_type") == "quarantine_cleared")
               .select("name_norm").distinct().withColumn("cleared_later", F.lit(True)))
    flagged = (alerts.join(mal.withColumn("in_osv_malicious", F.lit(True)), "name_norm", "left")
               .join(cleared, "name_norm", "left").na.fill({"in_osv_malicious": False, "cleared_later": False}))
    by_kind = (flagged.groupBy("takedown_kind").agg(
        F.count("*").alias("alerts"),
        F.sum(F.col("in_osv_malicious").cast("int")).alias("with_malicious_advisory"),
        F.round(100 * F.avg(F.col("in_osv_malicious").cast("int")), 1).alias("pct_with_advisory"),
        F.sum(F.col("cleared_later").cast("int")).alias("quarantine_cleared_later"),
        F.round(F.percentile_approx("online_hours", 0.5, 10000), 2).alias("median_hours_online")))
    table = save_csv(by_kind, OUT + "short_lived_vs_osv.csv")

    # Recall: of all malicious packages uploaded in this period with a measured lifetime, how many did the rule flag?
    span = alerts.agg(F.min("created_ts").alias("a"), F.max("takedown_ts").alias("b")).first()
    measured = (spark.read.parquet(str(GOLD / "malicious_lifetime"))
                .filter(F.col("online_since").between(span["a"], span["b"]) & (F.col("online_hours") >= 0))
                .select(F.col("package").alias("name_norm"), "online_hours").dropDuplicates(["name_norm"]))
    caught = measured.join(alerts.select("name_norm").distinct(), "name_norm").count()
    total = measured.count()
    within = measured.filter("online_hours <= 24").count()
    coverage = save_csv(pd.DataFrame([{"malicious_packages_measured": total, "gone_within_24h": within, "flagged_by_stream": caught,
                                       "recall_pct": round(100 * caught / max(total, 1), 1)}]), OUT + "short_lived_coverage.csv")
    return table, coverage


def main():
    spark = get_spark("07_evaluate", shuffle=8)
    truth = spark.read.parquet(str(GOLD / "stream_truth"))
    show = lambda t: print(t.to_string(index=False), "\n", flush=True)  # noqa: E731

    rows = []
    replay = STREAM / "sink_replay"
    if has_data(replay / "activity"):
        rows.append(completeness(spark, replay / "activity", truth, "replay, watermark 12 hours"))
        for table in evaluate_short_lived(spark):
            show(table)
        alerts = spark.read.parquet(str(replay / "new_maintainer")).dropDuplicates(["name_norm", "added_ts", "release_ts"])
        distinct = alerts.dropDuplicates(["name_norm", "added_ts"])
        days = max(1, alerts.agg(F.datediff(F.max("release_ts"), F.min("added_ts"))).first()[0] or 1)
        show(save_csv(pd.DataFrame([{"maintainer_changes_then_release": distinct.count(), "packages": distinct.select("name_norm").distinct().count(),
                                     "days_covered": days, "alerts_per_day": round(distinct.count() / days, 2)}]), OUT + "new_maintainer_alerts.csv"))
        show(save_csv(distinct.groupBy(F.year("added_ts").alias("year"), "role").count().orderBy("year", "role"), OUT + "new_maintainer_by_year.csv"))
        adv = spark.read.parquet(str(replay / "advisories")).dropDuplicates(["name_norm", "advisory_id"])
        band = F.when(F.col("severity") >= 9, "critical").when(F.col("severity") >= 7, "high").when(F.col("severity") >= 4, "medium") \
            .when(F.col("severity").isNotNull(), "low").otherwise("unknown")
        show(save_csv(adv.withColumn("severity_band", band).groupBy("action_type", "severity_band").count().orderBy("action_type", "severity_band"), OUT + "advisory_alerts_by_band.csv"))
        show(save_csv(adv.orderBy(F.desc("event_ts")).select("name_norm", "event_ts", "advisory_id", "severity", "direct_dependents", "reach").limit(25), OUT + "advisory_alerts_recent.csv"))

    for path in sorted(STREAM.glob("sink_wm_*")):
        if has_data(path / "activity"):
            meta = json.loads((path / "slice.json").read_text(encoding="utf-8"))
            row = completeness(spark, path / "activity", truth, "watermark " + meta["watermark"], meta["first_bucket"], meta["last_bucket"])
            progress = pd.read_csv(RESULTS / "part2" / f"progress_{path.name}_activity.csv")
            row["peak_state_rows"] = int(progress.state_rows.max())
            row["spark_rows_dropped"] = int(progress.dropped_late.sum())
            rows.append(row)
    if rows:
        show(save_csv(pd.DataFrame(rows), OUT + "completeness.csv"))

    # The live run: time from an event on PyPI to the start of the micro-batch that handled it.
    live = STREAM / "sink_live"
    if has_data(live / "heartbeat"):
        beat = spark.read.parquet(str(live / "heartbeat")).withColumn("s", F.unix_timestamp("alert_ts") - F.unix_timestamp("event_ts"))
        lat = beat.agg(F.count("*").alias("events"), F.percentile_approx("s", 0.5).alias("median_s"), F.percentile_approx("s", 0.95).alias("p95_s"),
                       F.max("s").alias("max_s"), F.min("event_ts").alias("first_event"), F.max("event_ts").alias("last_event"))
        show(save_csv(lat, OUT + "live_latency.csv"))
        show(save_csv(beat.groupBy("action_type").count().orderBy(F.desc("count")), OUT + "live_events_by_type.csv"))
        counts = {q: spark.read.parquet(str(live / q)).count() if has_data(live / q) else 0 for q in ("activity", "short_lived", "new_maintainer", "advisories")}
        show(save_csv(pd.DataFrame([{"query": k, "rows_written": v} for k, v in counts.items()]), OUT + "live_outputs.csv"))

    # Throughput per query from Spark's own progress reports.
    rows = []
    for path in sorted((RESULTS / "part2").glob("progress_sink_replay_*.csv")):
        p = pd.read_csv(path)
        busy = p[p.input_rows > 0]
        rows.append({"query": path.stem.replace("progress_sink_replay_", ""), "batches": len(busy),
                     "events": int(busy.input_rows.sum()),
                     "events_per_s_of_compute": round(busy.input_rows.sum() / (busy.trigger_ms.sum() / 1000), 0),
                     "median_batch_s": round(busy.trigger_ms.median() / 1000, 1),
                     "p95_batch_s": round(busy.trigger_ms.quantile(0.95) / 1000, 1),
                     "peak_state_rows": int(p.state_rows.max()), "peak_state_mb": p.state_memory_mb.max(),
                     "dropped_late": int(p.dropped_late.sum())})
    if rows:
        show(save_csv(pd.DataFrame(rows), OUT + "throughput.csv"))
    spark.stop()


if __name__ == "__main__":
    main()
