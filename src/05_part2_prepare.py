"""Part 2 (Velocity), preparation: turn the history into files a stream can receive.

The input to the stream is the raw changelog plus advisory-publication events.
A real feed is not perfectly ordered, so each event gets a simulated arrival time:
    event time + exponential delay (mean 5 minutes)
    0.2 % of events get a long delay of 1 to 48 hours, as an outage would cause.
Seeded, so reruns give the same files. Two sets of files come out:
    source/         the whole window, one file per 6 hours of arrival time
    source_hourly/  a slice cut per hour, for the watermark experiment: Spark only moves the
                    watermark between micro-batches, so a batch must be short for lateness to show

Also writes the static side of the stream, the watchlist of packages many others rely on,
and the batch truth the streaming results are compared with.
"""
import argparse

from pyspark.sql import functions as F

from common import classify_action, get_spark, norm_name
from config import DATA, GOLD, SILVER

WATCHLIST_MIN_DIRECT = 50     # a package with this many direct dependents is on the watchlist


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="2024-01-01")
    ap.add_argument("--end", default="2026-11-07")
    ap.add_argument("--slice-start", default="2026-09-01", help="first day of the hourly slice")
    ap.add_argument("--slice-days", type=int, default=10)
    args = ap.parse_args()

    spark = get_spark("05_prepare")
    window = (F.col("event_ts") >= args.start) & (F.col("event_ts") < args.end)

    events = (spark.read.parquet(str(SILVER / "events")).filter(window)
              .select("serial", "event_ts", "name", "version", "action", F.lit(None).cast("double").alias("severity")))

    flaws = spark.read.parquet(str(SILVER / "flaw_package"))
    advisories = (flaws.withColumnRenamed("disclosed_ts", "event_ts").filter(window)
                  .select(F.lit(None).cast("long").alias("serial"), "event_ts", F.col("package").alias("name"),
                          F.element_at("ids", 1).alias("version"),
                          F.when(F.col("is_malicious"), "advisory_malicious").otherwise("advisory_vulnerability").alias("action"),
                          "severity"))
    stream = events.unionByName(advisories)

    delay = (F.when(F.rand(42) < 0.002, 3600 + F.rand(43) * 47 * 3600)
             .otherwise(-300 * F.log(1 - F.rand(44))))
    stream = (stream.withColumn("arrival_s", F.unix_timestamp("event_ts") + delay)
              .withColumn("bucket", (F.col("arrival_s") / (6 * 3600)).cast("long") * (6 * 3600))
              .withColumn("delay_s", F.round(F.col("arrival_s") - F.unix_timestamp("event_ts"), 0))
              .withColumn("event_time", F.date_format("event_ts", "yyyy-MM-dd'T'HH:mm:ss'Z'")))
    # Fixed to Parquet here: rand() must not be drawn again for each of the outputs below.
    stream.write.mode("overwrite").parquet(str(DATA / "tmp_stream"))
    stream = spark.read.parquet(str(DATA / "tmp_stream"))

    fields = ["serial", "event_time", "name", "version", "action", "severity", "delay_s"]
    (stream.select(*fields, "bucket")
     .repartition("bucket").write.mode("overwrite").partitionBy("bucket").json(str(DATA / "stream" / "source")))

    first = spark.sql(f"SELECT unix_timestamp(timestamp'{args.slice_start} 00:00:00') AS s").first()["s"]
    last = first + args.slice_days * 86400
    hourly = (stream.filter((F.col("arrival_s") >= first) & (F.col("arrival_s") < last))
              .withColumn("bucket", (F.col("arrival_s") / 3600).cast("long") * 3600))
    (hourly.select(*fields, "bucket")
     .repartition("bucket").write.mode("overwrite").partitionBy("bucket").json(str(DATA / "stream" / "source_hourly")))

    # Batch truth: hourly counts of exactly the events the stream will receive.
    truth = (stream.withColumn("action_type", classify_action())
             .groupBy(F.date_trunc("hour", "event_ts").alias("hour"), "action_type").count())
    truth.write.mode("overwrite").parquet(str(GOLD / "stream_truth"))
    stream.agg(F.count("*").alias("events"), F.min("event_ts").alias("first"), F.max("event_ts").alias("last"),
               F.round(F.avg("delay_s")).alias("mean_delay_s"),
               F.sum((F.col("delay_s") > 3600).cast("int")).alias("delayed_over_1h")).show(truncate=False)

    v = spark.read.parquet(str(GOLD / "vertices_metrics"))
    rank = spark.read.parquet(str(GOLD / "ranking.parquet")).select("id", "reach", "n_open", "risk_history")
    watch = (v.filter(f"direct_dependents >= {WATCHLIST_MIN_DIRECT}").join(rank, "id", "left")
             .select(norm_name(F.col("id")).alias("name_norm"), "direct_dependents", "reach", "n_flaws", "pagerank"))
    watch.write.mode("overwrite").parquet(str(GOLD / "watchlist"))
    print("watchlist:", spark.read.parquet(str(GOLD / "watchlist")).count(), "packages")
    spark.stop()


if __name__ == "__main__":
    main()
