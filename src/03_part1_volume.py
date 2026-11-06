"""Part 1 (Volume): how fast does the Python ecosystem react to a security problem?

Joins the PyPI event log, OSV advisories, PyPI project metadata and deps.dev to answer:
  Q1  How long do malicious packages stay online, and does the advisory warn or only record?
  Q2  When does the fix ship relative to public disclosure?
  Q3  How many flaws are still open in the version pip installs today?
"""
from pyspark.sql import functions as F
from pyspark.sql.window import Window

from common import get_spark, save_csv
from config import GOLD, SILVER

OUT = "part1/"
SNAPSHOT = "2026-11-06"


def band(col):
    return (F.when(col >= 9, "1 critical").when(col >= 7, "2 high").when(col >= 4, "3 medium")
            .when(col.isNotNull(), "4 low").otherwise("5 unknown"))


def version_key(col):
    """1.2.0 and 1.2 are the same release: compare without a leading v or trailing zero groups."""
    return F.regexp_replace(F.regexp_replace(F.lower(col), r"^v", ""), r"(\.0+)+$", "")


def median(col, name):
    return F.round(F.percentile_approx(col, 0.5, 10000), 2).alias(name)


def percent(condition, name):
    return F.round(100 * F.avg(F.when(condition, 1.0).otherwise(0.0)), 1).alias(name)


def scale(events):
    return save_csv(events.groupBy("year").pivot("action_type", [
        "new_release", "add_file", "create", "remove_project", "quarantine", "maintainer_added"
    ]).count().orderBy("year").na.fill(0), OUT + "events_by_year.csv")


def join_coverage(flaws, events, projects, depsdev):
    """How well each pair of sources joins on the normalised project name."""
    logged = events.select(F.col("name_norm").alias("package")).distinct().withColumn("in_log", F.lit(True))
    crawled = projects.select("package").withColumn("has_metadata", F.lit(True))
    known = depsdev.select("package").withColumn("in_depsdev", F.lit(True))
    pkgs = flaws.groupBy("package").agg(F.max("is_malicious").alias("is_malicious"), F.min("is_malicious").alias("only_malicious"))
    table = (pkgs.withColumn("kind", F.when(F.col("only_malicious"), "only malicious records").otherwise("has vulnerabilities"))
             .join(logged, "package", "left").join(crawled, "package", "left").join(known, "package", "left")
             .groupBy("kind").agg(
                 F.count("*").alias("packages"),
                 percent(F.col("in_log").isNotNull(), "pct_in_changelog"),
                 percent(F.col("has_metadata").isNotNull(), "pct_live_on_pypi"),
                 percent(F.col("in_depsdev").isNotNull(), "pct_in_depsdev")))
    return save_csv(table, OUT + "join_coverage.csv")


def malicious_lifetime(spark, flaws, events):
    """Q1. A name can be reused, so each advisory is matched to the takedown nearest to it."""
    mal = flaws.filter("is_malicious").select("cluster_id", "package", "disclosed_ts")
    log = events.filter(F.col("action_type").isin("create", "new_release", "quarantine", "remove_project")) \
        .select(F.col("name_norm").alias("package"), "event_ts", "action_type")

    takedowns = log.filter(F.col("action_type").isin("quarantine", "remove_project"))
    # The nearest takedown at most 90 days before the advisory, or any time after it.
    candidates = (mal.join(takedowns, "package")
                  .filter(F.col("event_ts") >= F.expr("disclosed_ts - INTERVAL 90 DAYS")))
    first = Window.partitionBy("cluster_id", "package").orderBy("event_ts")
    taken = (candidates.withColumn("r", F.row_number().over(first)).filter("r = 1")
             .select("cluster_id", "package", F.col("event_ts").alias("takedown_ts"),
                     F.col("action_type").alias("takedown_kind")))

    # Upload = the last create (else first release) before that takedown.
    arrivals = log.filter(F.col("action_type").isin("create", "new_release")).select("package", F.col("event_ts").alias("arrival_ts"), "action_type")
    upload = (taken.join(arrivals, "package").filter("arrival_ts <= takedown_ts")
              .groupBy("cluster_id", "package").agg(
                  F.max(F.when(F.col("action_type") == "create", F.col("arrival_ts"))).alias("last_create"),
                  F.min("arrival_ts").alias("first_seen"))
              .withColumn("online_since", F.coalesce("last_create", "first_seen")))

    seen = log.select("package").distinct().withColumn("in_log", F.lit(True))
    table = (mal.join(taken, ["cluster_id", "package"], "left")
             .join(upload.select("cluster_id", "package", "online_since"), ["cluster_id", "package"], "left")
             .join(seen, "package", "left")
             .withColumn("online_hours", (F.unix_timestamp("takedown_ts") - F.unix_timestamp("online_since")) / 3600)
             .withColumn("advisory_after_takedown_hours", (F.unix_timestamp("disclosed_ts") - F.unix_timestamp("takedown_ts")) / 3600)
             .withColumn("takedown_year", F.year("takedown_ts")))
    table.write.mode("overwrite").parquet(str(GOLD / "malicious_lifetime"))
    table = spark.read.parquet(str(GOLD / "malicious_lifetime"))

    status = save_csv(table.withColumn("status",
                                       F.when(F.col("in_log").isNull(), "no event in the changelog")
                                       .when(F.col("takedown_ts").isNull(), "no takedown event near the advisory")
                                       .when(F.col("online_since").isNull(), "takedown, but no upload event before it")
                                       .otherwise("lifetime measured"))
                      .groupBy("status").count().orderBy(F.desc("count")), OUT + "malicious_join_status.csv")

    ok = table.filter(F.col("online_hours").isNotNull() & (F.col("online_hours") >= 0))
    by_year = save_csv(ok.groupBy("takedown_year").agg(
        F.count("*").alias("packages"),
        median("online_hours", "median_hours_online"),
        F.round(F.percentile_approx("online_hours", 0.9, 10000), 1).alias("p90_hours_online"),
        percent(F.col("online_hours") <= 1, "pct_gone_in_1h"),
        percent(F.col("online_hours") <= 24, "pct_gone_in_24h"),
        percent(F.col("online_hours") > 24 * 7, "pct_online_over_7d"),
        median("advisory_after_takedown_hours", "median_hours_advisory_after_takedown"),
        percent(F.col("disclosed_ts") < F.col("takedown_ts"), "pct_advisory_before_takedown"),
        percent(F.col("takedown_kind") == "quarantine", "pct_first_action_quarantine"),
    ).orderBy("takedown_year"), OUT + "malicious_lifetime_by_year.csv")

    bins = F.when(F.col("online_hours") <= 1, "1 up to 1h").when(F.col("online_hours") <= 6, "2 1-6h") \
        .when(F.col("online_hours") <= 24, "3 6-24h").when(F.col("online_hours") <= 72, "4 1-3d") \
        .when(F.col("online_hours") <= 168, "5 3-7d").when(F.col("online_hours") <= 720, "6 7-30d") \
        .when(F.col("online_hours") <= 8760, "7 1-12mo").otherwise("8 over 1y")
    save_csv(ok.withColumn("bin", bins).groupBy("bin").count().orderBy("bin"), OUT + "malicious_lifetime_hist.csv")
    return status, by_year


def quarantine_outcomes(flaws, events):
    """What happens after PyPI quarantines a project, and how often it was a false alarm."""
    q = (events.filter(F.col("action_type") == "quarantine").groupBy(F.col("name_norm").alias("package"))
         .agg(F.min("event_ts").alias("quarantined_ts")))
    later = events.filter(F.col("action_type").isin("quarantine_cleared", "remove_project")).select(
        F.col("name_norm").alias("package"), "action_type", F.col("event_ts").alias("after_ts"))
    outcomes = (q.join(later, "package", "left").filter(F.col("after_ts").isNull() | (F.col("after_ts") >= F.col("quarantined_ts")))
                .groupBy("package").agg(
                    F.max((F.col("action_type") == "quarantine_cleared").cast("int")).alias("cleared"),
                    F.max((F.col("action_type") == "remove_project").cast("int")).alias("removed")))
    mal = flaws.filter("is_malicious").select("package").distinct().withColumn("has_malicious_advisory", F.lit(1))
    t = (q.select("package").join(outcomes, "package", "left").join(mal, "package", "left").na.fill(0)
         .withColumn("outcome", F.when(F.col("cleared") == 1, "quarantine cleared")
                                 .when(F.col("removed") == 1, "project removed afterwards")
                                 .otherwise("still quarantined at the snapshot")))
    return save_csv(t.groupBy("outcome").agg(
        F.count("*").alias("projects"), F.sum("has_malicious_advisory").alias("with_malicious_advisory"),
    ).orderBy(F.desc("projects")), OUT + "quarantine_outcomes.csv")


def fix_timeline(spark, flaws, releases):
    """Q2. For each flaw on each package: first fix, first affected release, disclosure."""
    vulns = flaws.filter("NOT is_malicious")
    rel = releases.withColumn("key", version_key(F.col("version"))).select("package", "key", "upload_ts", "version")

    fixed = (vulns.select("cluster_id", "package", F.explode("fixed_versions").alias("fixed"))
             .withColumn("key", version_key(F.col("fixed"))))
    fix_times = (fixed.join(rel, ["package", "key"], "left").groupBy("cluster_id", "package").agg(
        F.min("upload_ts").alias("first_fix_ts"),
        F.count("fixed").alias("n_fix_listed")))

    affected = vulns.select("cluster_id", "package", F.explode("affected_versions").alias("version"))
    first_bad = (affected.join(releases.select("package", "version", "upload_ts"), ["package", "version"])
                 .groupBy("cluster_id", "package").agg(F.min("upload_ts").alias("first_affected_ts")))

    t = (vulns.drop("ids", "cvss3").join(fix_times, ["cluster_id", "package"], "left")
         .join(first_bad, ["cluster_id", "package"], "left")
         .withColumn("band", band(F.col("severity")))
         .withColumn("disclosure_year", F.year("disclosed_ts"))
         .withColumn("fix_lag_days", (F.unix_timestamp("first_fix_ts") - F.unix_timestamp("disclosed_ts")) / 86400)
         # Only when the advisory names a real start version. 'Introduced: 0' would date it to the first release ever.
         .withColumn("exposure_days", F.when(F.col("introduced_known"),
                                             (F.unix_timestamp("first_fix_ts") - F.unix_timestamp("first_affected_ts")) / 86400))
         .withColumn("fix_status",
                     F.when(F.col("fixed_versions").isNull(), "no fix listed")
                      .when(F.col("first_fix_ts").isNull(), "fix listed, version not on PyPI")
                      # A record a year after the fix is a late entry in a database, not a disclosure.
                      .when(F.col("fix_lag_days") <= -365, "record over a year after the fix")
                      .when(F.col("fix_lag_days") <= -1, "fix before disclosure")
                      .when(F.col("fix_lag_days") <= 7, "fix within a week of disclosure")
                      .when(F.col("fix_lag_days") <= 30, "fix 1-4 weeks after")
                      .otherwise("fix over 30 days after")))
    t.write.mode("overwrite").parquet(str(GOLD / "flaw_timeline"))
    t = spark.read.parquet(str(GOLD / "flaw_timeline"))

    save_csv(t.groupBy("fix_status").count().orderBy(F.desc("count")), OUT + "fix_status.csv")
    # Back-filled records are left out of the timing: their date says nothing about disclosure.
    timed = t.filter(F.col("fix_lag_days") > -365)
    agg = [F.count("*").alias("flaws"),
           median("fix_lag_days", "median_fix_lag_days"),
           percent(F.col("fix_lag_days") <= -1, "pct_fixed_before_disclosure"),
           percent(F.col("fix_lag_days") > 30, "pct_fixed_over_30d_after"),
           median("exposure_days", "median_exposure_days")]
    by_band = save_csv(timed.groupBy("band").agg(*agg).orderBy("band"), OUT + "fix_by_severity.csv")
    by_year = save_csv(timed.filter("disclosure_year >= 2015").groupBy("disclosure_year").agg(*agg).orderBy("disclosure_year"),
                       OUT + "fix_by_year.csv")
    return t, by_band, by_year


def open_exposure(spark, timeline, projects):
    """Q3. A flaw is open when the version pip installs today is on its affected list."""
    p = projects.select("package", "latest_version", "last_release", "n_releases", "n_maintainers", "pypi_vuln_ids")
    t = timeline.join(p, "package", "left")
    live = t.filter(F.col("latest_version").isNotNull())

    live = live.withColumn("has_list", F.size(F.coalesce("affected_versions", F.array())) > 0) \
               .withColumn("is_open", F.expr("array_contains(affected_versions, latest_version)"))\
               .withColumn("is_open", F.coalesce(F.col("is_open"), F.lit(False)))
    live = live.withColumn("years_since_release",
                           F.round(F.datediff(F.lit(SNAPSHOT), "last_release") / 365.25, 2))
    live.write.mode("overwrite").parquet(str(GOLD / "flaw_status"))
    live = spark.read.parquet(str(GOLD / "flaw_status"))

    save_csv(live.groupBy("band").agg(
        F.count("*").alias("flaws_on_live_packages"),
        F.sum(F.col("is_open").cast("int")).alias("open_in_latest"),
        percent(F.col("is_open"), "pct_open"),
        # Without a list of affected versions the rule cannot say 'open', so these count as not open.
        F.sum((~F.col("has_list")).cast("int")).alias("no_version_list"),
    ).orderBy("band"), OUT + "open_by_severity.csv")

    open_ = live.filter("is_open").withColumn(
        "maintenance",
        F.when(F.col("years_since_release") >= 2, "no release for 2+ years")
         .when(F.col("years_since_release") >= 1, "last release 1-2 years ago")
         .otherwise("released in the last year"))
    save_csv(open_.groupBy("maintenance").agg(
        F.count("*").alias("open_flaws"), F.countDistinct("package").alias("packages"),
        percent(F.col("fixed_versions").isNull(), "pct_no_fix_listed"),
    ).orderBy("maintenance"), OUT + "open_by_maintenance.csv")
    return live


def validate_open_rule(flaws, live):
    """Compare the 'open' rule with the list PyPI itself publishes for the latest version."""
    ids = flaws.select("cluster_id", "package", "ids")
    v = (live.join(ids, ["cluster_id", "package"])
         .withColumn("pypi_says_open", F.size(F.array_intersect("ids", F.coalesce("pypi_vuln_ids", F.array().cast("array<string>")))) > 0))
    table = v.groupBy("is_open", "pypi_says_open").count().orderBy("is_open", "pypi_says_open")
    return save_csv(table, OUT + "open_rule_vs_pypi.csv")


def exposure_vs_reach(spark, depsdev):
    """Are open flaws sitting on widely used packages? deps.dev gives an outside measure of use."""
    live = spark.read.parquet(str(GOLD / "flaw_status"))
    per_pkg = live.groupBy("package").agg(
        F.sum(F.col("is_open").cast("int")).alias("open_flaws"), F.count("*").alias("flaws"))
    bucket = F.when(F.col("dependentCount") == 0, "1 none").when(F.col("dependentCount") < 10, "2 1-9") \
        .when(F.col("dependentCount") < 100, "3 10-99").when(F.col("dependentCount") < 1000, "4 100-999") \
        .otherwise("5 1000+")
    return save_csv(per_pkg.join(depsdev, "package").withColumn("depsdev_dependents", bucket)
                    .groupBy("depsdev_dependents").agg(
                        F.count("*").alias("packages"),
                        F.sum("flaws").alias("flaws"),
                        F.sum("open_flaws").alias("open_flaws"),
                        percent(F.col("open_flaws") > 0, "pct_packages_with_open_flaw"),
                    ).orderBy("depsdev_dependents"), OUT + "open_vs_depsdev_dependents.csv")


def weak_types(spark):
    adv = spark.read.parquet(str(SILVER / "advisories"))
    return save_csv(adv.filter("kind = 'vulnerability'").select("id", F.explode("cwe_ids").alias("cwe")).distinct()
                    .groupBy("cwe").count().orderBy(F.desc("count")).limit(15), OUT + "top_cwe.csv")


def main():
    spark = get_spark("03_part1")
    events = spark.read.parquet(str(SILVER / "events"))
    flaws = spark.read.parquet(str(SILVER / "flaw_package"))
    releases = spark.read.parquet(str(SILVER / "releases"))
    projects = spark.read.parquet(str(SILVER / "projects"))
    depsdev = spark.read.parquet(str(SILVER / "depsdev"))

    show = lambda pdf: print(pdf.to_string(index=False), "\n", flush=True)  # noqa: E731
    show(scale(events))
    show(join_coverage(flaws, events, projects, depsdev))
    for table in malicious_lifetime(spark, flaws, events):
        show(table)
    show(quarantine_outcomes(flaws, events))
    timeline, by_band, by_year = fix_timeline(spark, flaws, releases)
    show(by_band)
    show(by_year)
    live = open_exposure(spark, timeline, projects)
    show(validate_open_rule(flaws, live))
    show(exposure_vs_reach(spark, depsdev))
    show(weak_types(spark))
    spark.stop()


if __name__ == "__main__":
    main()
