"""Spark session and small helpers shared by the pipeline steps."""
import csv
import os

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

from config import RESULTS


def get_spark(app, shuffle=48):
    builder = (SparkSession.builder.appName(app)
               .master(os.environ.get("DPA_MASTER", "local[8]"))
               .config("spark.driver.memory", os.environ.get("DPA_DRIVER_MEMORY", "5g"))
               .config("spark.sql.shuffle.partitions", shuffle)
               .config("spark.sql.session.timeZone", "UTC")
               .config("spark.sql.adaptive.enabled", "true")
               .config("spark.ui.showConsoleProgress", "false"))
    spark = builder.getOrCreate()
    spark.sparkContext.setLogLevel("WARN")
    return spark


def norm_name(col):
    """PEP 503 normalised project name: the one key shared by OSV, PyPI and deps.dev."""
    return F.lower(F.regexp_replace(col, r"[-_.]+", "-"))


def classify_action(action="action", version="version"):
    """Free-text changelog action -> event type. Shared by the batch and streaming jobs."""
    a = F.coalesce(F.col(action), F.lit(""))
    blank = F.col(version).isNull() | (F.trim(F.col(version)) == "")
    return (F.when(a == "create", "create")
            .when(a == "new release", "new_release")
            .when(a == "project quarantined", "quarantine")
            .when(a == "project quarantine cleared", "quarantine_cleared")
            .when(a == "remove project", "remove_project")
            # Before about 2017 a bare 'remove' meant the whole project if no version was given.
            .when((a == "remove") & blank, "remove_project")
            .when(a.isin("remove", "remove release"), "remove_release")
            .when(a.startswith("yank release"), "yank_release")
            .when(a.startswith("unyank release"), "unyank_release")
            .when(a.rlike(r"^add .*file "), "add_file")
            .when(a.startswith("remove file"), "remove_file")
            # An invitation changes nothing until accepted, so only these two count.
            .when(a.rlike(r"^(add|accepted) (Owner|Maintainer)"), "maintainer_added")
            .when(a.rlike(r"^remove (Owner|Maintainer)"), "maintainer_removed")
            .when(a.startswith("advisory"), a)
            .otherwise("other"))


def save_csv(df, relative_path):
    """Write a small result table as one CSV in results/, without Spark's folder layout."""
    pdf = df.toPandas() if hasattr(df, "toPandas") else df
    path = RESULTS / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    pdf.to_csv(path, index=False, encoding="utf-8", lineterminator="\n")
    return pdf


class RowLog:
    """Row counts before and after each cleaning step, for the report."""

    def __init__(self, filename="cleaning_log.csv"):
        self.path = RESULTS / filename
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.rows = []

    def add(self, table, step, before, after, reason, modified=0):
        self.rows.append([table, step, before, after, before - after, modified, reason])
        print(f"[clean] {table:<13} {step:<34} {before:>12,} -> {after:>12,}"
              f"  removed {before - after:>10,}  modified {modified:>10,}", flush=True)
        # Written after each step, so a crash still leaves the log so far.
        with open(self.path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["table", "step", "rows_before", "rows_after", "rows_removed", "rows_modified", "reason"])
            w.writerows(self.rows)
