"""Part 2 (Velocity): Structured Streaming over PyPI's event feed.

    python src/06_part2_stream.py replay                   # the prepared history, fast-forwarded
    python src/06_part2_stream.py watermarks               # completeness vs watermark experiment
    python src/06_part2_stream.py live --minutes 30        # the real feed, right now

Four queries run over the same input folder:
  Q1 activity     event counts per type in event-time windows, with a watermark
  Q2 short_lived  a project taken down within 24h of its creation (stream-stream join)
  Q3 new_maintainer  a new maintainer on a watchlist package, then a release within 72h
                  (stream-static + stream-stream join). Routine in most cases: a prompt to look, not a verdict.
  Q4 advisories   a new advisory on a watchlist package, flagged at once (stream-static join)
The live run adds a heartbeat: every event with the time it was processed, to measure latency.
"""
import argparse
import csv
import json
import os
import shutil
import threading
import time
import xmlrpc.client
from datetime import datetime, timezone
from pathlib import Path

from pyspark.sql import functions as F
from pyspark.sql.types import DoubleType, LongType, StringType, StructField, StructType

from common import classify_action, get_spark, norm_name
from config import DATA, GOLD, RESULTS, pypi_client

STREAM = DATA / "stream"
# Streaming state goes on the Docker volume when there is one: a bind mount is very slow for it.
CHECKPOINTS = Path(os.environ.get("DPA_STREAM_STATE", "/tmp/spark/checkpoints"))
OUT = RESULTS / "part2"
PROGRESS_FIELDS = ["batch", "timestamp", "input_rows", "input_rows_per_s", "processed_rows_per_s", "trigger_ms",
                   "watermark", "state_rows", "state_memory_mb", "dropped_late"]

SCHEMA = StructType([
    StructField("serial", LongType()), StructField("event_time", StringType()), StructField("name", StringType()),
    StructField("version", StringType()), StructField("action", StringType()), StructField("severity", DoubleType()),
    StructField("delay_s", DoubleType()),
])


def source(spark, folder, max_files, watermark):
    raw = spark.readStream.schema(SCHEMA).option("maxFilesPerTrigger", max_files).json(str(folder))
    return (raw.withColumn("event_ts", F.to_timestamp("event_time", "yyyy-MM-dd'T'HH:mm:ss'Z'"))
            # The live feed still holds 'user:<login>' admin events, which batch cleaning already removed.
            .filter(F.col("name").isNotNull() & F.col("event_ts").isNotNull() & ~F.col("name").contains(":"))
            .withColumn("name_norm", norm_name(F.col("name")))
            .withColumn("action_type", classify_action())
            .withWatermark("event_ts", watermark))


def q_activity(events, window):
    return (events.groupBy(F.window("event_ts", window).alias("w"), "action_type").count()
            .select(F.col("w.start").alias("window_start"), "action_type", "count"))


def q_short_lived(events):
    created = events.filter(F.col("action_type") == "create").select(
        F.col("name_norm").alias("c_name"), F.col("event_ts").alias("created_ts"))
    gone = events.filter(F.col("action_type").isin("quarantine", "remove_project")).select(
        F.col("name_norm").alias("t_name"), F.col("event_ts").alias("takedown_ts"), F.col("action_type").alias("takedown_kind"))
    joined = created.join(gone, F.expr("""
        c_name = t_name AND takedown_ts >= created_ts AND takedown_ts <= created_ts + INTERVAL 24 HOURS"""))
    return joined.select(F.col("c_name").alias("name_norm"), "created_ts", "takedown_ts", "takedown_kind",
                         ((F.unix_timestamp("takedown_ts") - F.unix_timestamp("created_ts")) / 3600).alias("online_hours"),
                         F.current_timestamp().alias("alert_ts"))


def q_new_maintainer(events, watchlist):
    added = (events.filter(F.col("action_type") == "maintainer_added").join(F.broadcast(watchlist), "name_norm")
             .select(F.col("name_norm").alias("a_name"), F.col("event_ts").alias("added_ts"),
                     F.split("action", " ").getItem(1).alias("role"), "direct_dependents", "reach"))
    release = events.filter(F.col("action_type") == "new_release").select(
        F.col("name_norm").alias("r_name"), F.col("event_ts").alias("release_ts"), F.col("version").alias("release"))
    joined = added.join(release, F.expr("""
        a_name = r_name AND release_ts >= added_ts AND release_ts <= added_ts + INTERVAL 72 HOURS"""))
    # The maintainer's user name is never carried: the signal is about packages, not people.
    return joined.select(F.col("a_name").alias("name_norm"), "added_ts", "release_ts", "release", "role",
                         "direct_dependents", "reach", F.current_timestamp().alias("alert_ts"))


def q_advisories(events, watchlist):
    return (events.filter(F.col("action_type").startswith("advisory")).join(F.broadcast(watchlist), "name_norm")
            .select("name_norm", "event_ts", "action_type", F.col("version").alias("advisory_id"), "severity",
                    "direct_dependents", "reach", "n_flaws", F.current_timestamp().alias("alert_ts")))


def q_heartbeat(events):
    return events.select("name_norm", "event_ts", "action_type", F.current_timestamp().alias("alert_ts"))


class Replay(threading.Thread):
    """Moves one prepared file into the input folder every `pace` seconds, oldest arrival first."""

    def __init__(self, inbox, pace, files):
        super().__init__(daemon=True)
        self.inbox, self.pace, self.files, self.finished = inbox, pace, files, False

    def run(self):
        for i, folder in enumerate(self.files):
            part = next(folder.glob("part-*.json"), None)
            if part is not None:
                # Copy under a hidden name, then rename: Spark must never see a half-written file.
                shutil.copyfile(part, self.inbox / f".{folder.name}.tmp")
                os.replace(self.inbox / f".{folder.name}.tmp", self.inbox / f"{folder.name}.json")
            if i % 200 == 0:
                print(f"replay: {i}/{len(self.files)} files", flush=True)
            time.sleep(self.pace)
        self.finished = True


class LiveFeed(threading.Thread):
    """Polls PyPI's real changelog and drops each batch of new events in the input folder."""

    def __init__(self, inbox, minutes, poll=30):
        super().__init__(daemon=True)
        self.inbox, self.poll, self.finished = inbox, poll, False
        self.deadline = time.time() + minutes * 60
        self.client = pypi_client()
        self.serial = self.client.changelog_last_serial()
        self.fetched = 0

    def run(self):
        while time.time() < self.deadline:
            time.sleep(self.poll)
            try:
                batch = self.client.changelog_since_serial(self.serial)
            except (OSError, xmlrpc.client.Error) as e:
                print("live: poll failed, next try in", self.poll, "s:", repr(e)[:120], flush=True)
                continue
            if not batch:
                continue
            self.serial = batch[-1][4]
            self.fetched += len(batch)
            path = self.inbox / f"{self.serial}.json"
            tmp = self.inbox / f".{self.serial}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                for name, version, ts, action, serial in batch:
                    when = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    f.write(json.dumps({"serial": serial, "event_time": when, "name": name,
                                        "version": version, "action": action}) + "\n")
            os.replace(tmp, path)
        self.finished = True


def log_progress(queries, writers, seen):
    """Record each finished micro-batch of each query."""
    for name, q in queries.items():
        for p in q.recentProgress:
            if (name, p["batchId"]) in seen:
                continue
            seen.add((name, p["batchId"]))
            state = p.get("stateOperators") or []
            # A self-join reads the same folder twice, so Spark's total counts each event twice.
            rows = p["sources"][0]["numInputRows"]
            ms = p["durationMs"].get("triggerExecution") or 0
            writers[name].writerow({
                "batch": p["batchId"], "timestamp": p["timestamp"], "input_rows": rows,
                "input_rows_per_s": round(p["sources"][0].get("inputRowsPerSecond") or 0, 1),
                "processed_rows_per_s": round(rows / (ms / 1000), 1) if ms else 0,
                "trigger_ms": ms,
                "watermark": (p.get("eventTime") or {}).get("watermark"),
                "state_rows": sum(s.get("numRowsTotal", 0) for s in state),
                "state_memory_mb": round(sum(s.get("memoryUsedBytes", 0) for s in state) / 1e6, 1),
                "dropped_late": sum(s.get("numRowsDroppedByWatermark", 0) for s in state),
            })


def run_queries(spark, inbox, sink, make_feed, wm, window, max_files, trigger, names):
    """Start the queries, feed them, and stop once the input is drained."""
    for folder in (inbox, sink):
        shutil.rmtree(folder, ignore_errors=True)
        folder.mkdir(parents=True)
    state = CHECKPOINTS / sink.name
    shutil.rmtree(state, ignore_errors=True)
    OUT.mkdir(parents=True, exist_ok=True)

    events = source(spark, inbox, max_files, wm)
    watchlist = spark.read.parquet(str(GOLD / "watchlist"))
    plans = {
        "activity": lambda: q_activity(events, window),
        "short_lived": lambda: q_short_lived(events),
        "new_maintainer": lambda: q_new_maintainer(events, watchlist),
        "advisories": lambda: q_advisories(events, watchlist),
        "heartbeat": lambda: q_heartbeat(events),
    }
    queries = {}
    files, writers = [], {}
    for name in names:
        queries[name] = (plans[name]().writeStream.queryName(f"{sink.name}_{name}").outputMode("append").format("parquet")
                         .option("path", str(sink / name)).option("checkpointLocation", str(state / name))
                         .trigger(processingTime=trigger).start())
        f = open(OUT / f"progress_{sink.name}_{name}.csv", "w", newline="", encoding="utf-8")
        w = csv.DictWriter(f, PROGRESS_FIELDS, lineterminator="\n")
        w.writeheader()
        files.append(f)
        writers[name] = w

    started = time.time()
    seen = set()
    feed = make_feed(inbox)
    feed.start()
    idle = 0
    try:
        while True:
            time.sleep(10)
            for q in queries.values():
                if q.exception():
                    raise RuntimeError(f"{q.name}: {q.exception()}")
            log_progress(queries, writers, seen)
            for f in files:
                f.flush()
            busy = any(q.lastProgress is None or q.lastProgress["numInputRows"] > 0 or q.status["isDataAvailable"]
                       for q in queries.values())
            idle = 0 if (busy or not feed.finished) else idle + 1
            if idle >= 3:
                break
    finally:
        for q in queries.values():
            q.stop()
        log_progress(queries, writers, seen)
        for f in files:
            f.close()
    shutil.rmtree(inbox, ignore_errors=True)   # a copy of the source, not needed once processed
    return time.time() - started, feed


def buckets(folder):
    return sorted(folder.glob("bucket=*"), key=lambda p: int(p.name.split("=")[1]))


def replay(spark, args):
    files = buckets(STREAM / "source")
    elapsed, _ = run_queries(spark, STREAM / "inbox_replay", STREAM / "sink_replay", lambda d: Replay(d, args.pace, files),
                             args.watermark, "1 hour", args.max_files, "5 seconds",
                             ["activity", "short_lived", "new_maintainer", "advisories"])
    print(f"replay finished in {elapsed / 60:.1f} min", flush=True)


def live(spark, args):
    # Short windows and a short watermark: a live run lasts minutes, not years.
    elapsed, feed = run_queries(spark, STREAM / "inbox_live", STREAM / "sink_live", lambda d: LiveFeed(d, args.minutes),
                                "2 minutes", "1 minute", 100, "10 seconds",
                                ["activity", "short_lived", "new_maintainer", "advisories", "heartbeat"])
    print(f"live finished after {elapsed / 60:.1f} min, {feed.fetched:,} events fetched", flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "live_run.json").write_text(json.dumps({
        "minutes": round(elapsed / 60, 1), "events_fetched": feed.fetched, "poll_seconds": feed.poll,
        "trigger_seconds": 10, "finished_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}), encoding="utf-8")


def watermarks(spark, args):
    """Same hourly input, different watermarks: how much late data does each one lose?"""
    files = buckets(STREAM / "source_hourly")
    for wm in args.watermarks.split(","):
        tag = "wm_" + wm.strip().replace(" ", "")
        sink = STREAM / f"sink_{tag}"
        # One file per micro-batch, so each batch covers one hour of arrivals.
        elapsed, _ = run_queries(spark, STREAM / f"inbox_{tag}", sink, lambda d: Replay(d, args.wm_pace, files),
                                 wm.strip(), "1 hour", 1, "1 second", ["activity"])
        (sink / "slice.json").write_text(json.dumps({
            "watermark": wm.strip(), "first_bucket": int(files[0].name.split("=")[1]),
            "last_bucket": int(files[-1].name.split("=")[1])}), encoding="utf-8")
        print(f"watermark {wm}: {elapsed:.0f} s", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["replay", "live", "watermarks"])
    ap.add_argument("--pace", type=float, default=0.5, help="seconds between replayed files (6 hours of history each)")
    ap.add_argument("--max-files", type=int, default=8, help="files per micro-batch in the replay")
    ap.add_argument("--watermark", default="12 hours")
    ap.add_argument("--minutes", type=float, default=30)
    ap.add_argument("--watermarks", default="10 minutes,1 hour,6 hours,24 hours,48 hours")
    ap.add_argument("--wm-pace", type=float, default=1.0, help="seconds between files in the watermark experiment")
    args = ap.parse_args()
    spark = get_spark("06_part2", shuffle=8)
    {"replay": replay, "live": live, "watermarks": watermarks}[args.mode](spark, args)
    spark.stop()


if __name__ == "__main__":
    main()
