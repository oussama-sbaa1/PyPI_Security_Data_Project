"""Bronze -> silver. Every step logs how many rows it removes or changes, and why."""
import pandas as pd
from graphframes import GraphFrame
from pyspark.sql import functions as F
from pyspark.sql.types import BooleanType, DoubleType, StringType, StructField, StructType
from pyspark.sql.window import Window

from common import RowLog, classify_action, get_spark, norm_name, save_csv
from config import BRONZE, CHANGELOG_END_SERIAL, DATA, SILVER
from cvss import base_score
from depparse import parse_requirement

PYPI_START = "2002-01-01"          # PyPI did not exist before this
SNAPSHOT_END = "2026-11-07"        # the day after the changelog cut
LABEL_MIDPOINT = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "LOW": 2.0}  # centres of the CVSS bands


def write(df, name):
    df.write.mode("overwrite").parquet(str(SILVER / name))
    return df.sparkSession.read.parquet(str(SILVER / name))


def out_of_order(df):
    """How far an event's clock runs behind the newest clock seen before it, in serial order.

    Saved for Part 2, where it sets the lower limit for a sensible watermark. Measured since 2024:
    older history holds a few events with timestamps years off.
    """
    # Serial blocks keep the window small, and a disorder of minutes never spans many serials.
    block = Window.partitionBy((F.col("serial") / 1000000).cast("long")).orderBy("serial")
    seen = df.filter(F.col("event_ts") >= "2024-01-01").select("serial", "timestamp").withColumn(
        "newest_before", F.max("timestamp").over(block.rowsBetween(Window.unboundedPreceding, -1)))
    late = seen.withColumn("late_s", F.col("newest_before") - F.col("timestamp"))
    row = late.agg(F.count("*").alias("events"), F.sum((F.col("late_s") > 0).cast("int")).alias("behind_clock"),
                   F.percentile_approx(F.when(F.col("late_s") > 0, F.col("late_s")), [0.5, 0.9, 0.99, 0.999]).alias("p"),
                   F.max("late_s").alias("max_s")).first()
    table = pd.DataFrame([{"events_since_2024": row["events"], "behind_clock": row["behind_clock"],
                           "pct_behind_clock": round(100 * row["behind_clock"] / max(row["events"], 1), 2),
                           "p50_s": row["p"][0], "p90_s": row["p"][1], "p99_s": row["p"][2], "p999_s": row["p"][3],
                           "max_s": row["max_s"]}])
    print(save_csv(table, "part2/real_disorder.csv").to_string(index=False), flush=True)
    return row["max_s"]


def clean_changelog(spark, log):
    df = spark.read.parquet(str(BRONZE / "changelog"))
    n0 = df.count()

    df = df.filter(F.col("_corrupt").isNull())
    n_ok = df.count()
    log.add("events", "CSV line that does not parse", n0, n_ok, "Wrong number of columns or a non-numeric field")

    df = df.filter(F.col("name").isNotNull() & F.col("timestamp").isNotNull() & F.col("serial").isNotNull())
    n1 = df.count()
    log.add("events", "missing name/timestamp/serial", n_ok, n1, "An event without these cannot be placed or joined")

    # 'nuke user' events use the name field for "user:<login>". They are not projects, and hold user names.
    df = df.filter(~F.col("name").contains(":"))
    n1b = df.count()
    log.add("events", "pseudo-project name (user:...)", n1, n1b, "Admin actions on accounts, not on projects")
    n1 = n1b

    df = df.dropDuplicates(["serial"])
    n2 = df.count()
    log.add("events", "duplicate serial", n1, n2, "Serial is PyPI's unique event id")

    df = df.withColumn("event_ts", F.col("timestamp").cast("timestamp"))
    df = df.filter((F.col("event_ts") >= PYPI_START) & (F.col("event_ts") < SNAPSHOT_END)
                   & (F.col("serial") <= CHANGELOG_END_SERIAL))
    n3 = df.count()
    log.add("events", "timestamp outside PyPI's lifetime", n2, n3, "Impossible dates; bounds 2002-01-01 to snapshot day")

    version_blank = F.col("version").isNull() | (F.trim("version") == "")
    df = (df.withColumn("version", F.when(version_blank, None).otherwise(F.col("version")))
          .withColumn("name_norm", norm_name(F.col("name")))
          .withColumn("action_type", classify_action())
          .withColumn("year", F.year("event_ts")))

    behind = out_of_order(df)
    log.add("events", "timestamp behind an earlier serial", n3, n3,
            f"Kept: PyPI's own clock disorder (largest since 2024: {behind} s). Serial stays the order, event_ts the time",
            modified=0)

    renamed = df.filter(F.col("name") != F.col("name_norm")).count()
    log.add("events", "normalise project name (PEP 503)", n3, n3,
            "Same project is written Foo_Bar and foo-bar across sources", modified=renamed)

    df = write(df.select("serial", "event_ts", "year", "name", "name_norm", "version", "action_type", "action"), "events")
    return df


def clean_advisories(spark, log):
    raw = spark.read.parquet(str(BRONZE / "osv"))
    n0 = raw.count()

    df = raw.filter(F.col("withdrawn").isNull())
    n1 = df.count()
    log.add("advisories", "withdrawn records", n0, n1, "Retracted by their publisher, so not real vulnerabilities")

    df = df.dropDuplicates(["id"])
    n2 = df.count()
    log.add("advisories", "duplicate id", n1, n2, "Each file should be one advisory")

    def ts(col):  # OSV has nanoseconds in some rows; Spark keeps seconds here, which is plenty
        return F.to_timestamp(F.substring(col, 1, 19), "yyyy-MM-dd'T'HH:mm:ss")

    df = (df.withColumn("published_ts", ts("published")).withColumn("modified_ts", ts("modified"))
            .withColumn("nvd_ts", ts("database_specific.nvd_published_at")))
    df = df.filter(F.col("published_ts").isNotNull() & (F.col("published_ts") < SNAPSHOT_END))
    n3 = df.count()
    log.add("advisories", "unreadable or future published date", n2, n3, "Event time is required by all three parts")

    inverted = df.filter(F.col("modified_ts") < F.col("published_ts")).count()
    df = df.withColumn("modified_ts", F.greatest("modified_ts", "published_ts"))
    log.add("advisories", "modified earlier than published", n3, n3,
            "Kept, modified raised to published: the publish date is the one we use", modified=inverted)

    @F.udf(DoubleType())
    def cvss3(rows):
        scores = [base_score(r["score"]) for r in rows or [] if r["type"] == "CVSS_V3"]
        scores = [x for x in scores if x is not None]
        return max(scores) if scores else None

    df = (df.withColumn("cvss3", cvss3("severity"))
            .withColumn("label", F.upper("database_specific.severity"))
            .withColumn("kind", F.when(F.col("id").startswith("MAL-"), "malicious").otherwise("vulnerability"))
            .withColumn("cwe_ids", F.col("database_specific.cwe_ids")))
    df = write(df.drop("severity", "database_specific", "withdrawn", "published", "modified"), "advisories")

    # ---- The same flaw is often published twice (GHSA and PYSEC). Alias links join them. -------------
    ids = df.select("id").distinct()
    alias_edges = (df.select(F.col("id").alias("src"), F.explode("aliases").alias("dst")).distinct())
    vertices = ids.union(alias_edges.select(F.col("dst").alias("id"))).distinct()
    spark.sparkContext.setCheckpointDir(str(DATA / "checkpoints"))
    components = GraphFrame(vertices, alias_edges).connectedComponents()
    clusters = components.select("id", F.col("component").cast("string").alias("cluster_id"))
    df = df.join(clusters, "id", "left")

    n_clusters = df.select("cluster_id").distinct().count()
    log.add("advisories", "merge aliases into one flaw", n3, n_clusters,
            "GHSA/PYSEC/CVE records of one flaw counted once (rows kept, grouped by cluster)")

    # ---- One row per flaw per package ---------------------------------------------------------------
    midpoint = F.create_map(*[F.lit(x) for kv in LABEL_MIDPOINT.items() for x in kv])
    flaws = df.groupBy("cluster_id").agg(
        F.array_sort(F.collect_set("id")).alias("ids"),
        F.max(F.col("kind") == "malicious").alias("is_malicious"),
        F.least(F.min("published_ts"), F.min("nvd_ts")).alias("disclosed_ts"),
        F.max("cvss3").alias("cvss3"),
        F.max(midpoint[F.col("label")]).alias("label_score"),
    )
    flaws = (flaws
             .withColumn("severity", F.coalesce("cvss3", "label_score"))
             .withColumn("severity_source",
                         F.when(F.col("cvss3").isNotNull(), "cvss3")
                          .when(F.col("label_score").isNotNull(), "label")
                          .otherwise("none"))
             .drop("label_score"))

    exploded = (df.select("cluster_id", F.explode("affected").alias("a"))
                .filter(F.col("a.package.ecosystem") == "PyPI")
                .withColumn("package", norm_name(F.col("a.package.name"))))
    n4 = exploded.count()
    no_info = exploded.filter(F.size("a.ranges") == 0).filter(F.coalesce(F.size("a.versions"), F.lit(0)) <= 0).count()

    events = (exploded.select("cluster_id", "package", F.explode("a.ranges").alias("r"))
              .filter(F.col("r.type") != "GIT")   # commit hashes, not versions
              .select("cluster_id", "package", F.explode("r.events").alias("e")))
    fixes = (events.filter(F.col("e.fixed").isNotNull())
             .groupBy("cluster_id", "package").agg(F.array_sort(F.collect_set("e.fixed")).alias("fixed_versions")))
    # 'introduced: 0' usually means "unknown, assume all", so only a real version dates the flaw's start.
    starts = (events.filter(F.col("e.introduced").isNotNull() & (F.col("e.introduced") != "0"))
              .select("cluster_id", "package").distinct().withColumn("introduced_known", F.lit(True)))

    versions = (exploded.select("cluster_id", "package", F.explode("a.versions").alias("v"))
                .groupBy("cluster_id", "package").agg(F.array_sort(F.collect_set("v")).alias("affected_versions")))
    pairs = exploded.select("cluster_id", "package").distinct()
    n5 = pairs.count()
    log.add("flaw_package", "one row per flaw and package", n4, n5,
            f"An advisory may repeat a package for each range ({no_info:,} entries give no version information)")

    out = (pairs.join(flaws, "cluster_id").join(fixes, ["cluster_id", "package"], "left")
           .join(versions, ["cluster_id", "package"], "left").join(starts, ["cluster_id", "package"], "left")
           .na.fill({"introduced_known": False}))
    out = write(out, "flaw_package")
    no_sev = out.filter(~F.col("is_malicious") & (F.col("severity_source") == "none")).count()
    log.add("flaw_package", "vulnerabilities with no severity", no_sev, no_sev,
            "Kept. No score in any aliased record; ranking imputes the median, flagged in Part 3")
    return out


def clean_projects(spark, log):
    raw = spark.read.parquet(str(BRONZE / "projects"))
    n0 = raw.count()
    df = raw.withColumn("package", norm_name(F.coalesce("info.name", "requested_name")))
    df = df.filter(F.col("package").isNotNull())
    # A project asked for by two spellings appears twice in the crawl: keep the newest copy.
    newest = Window.partitionBy("package").orderBy(F.desc("last_serial"))
    df = df.withColumn("rank", F.row_number().over(newest)).filter(F.col("rank") == 1).drop("rank")
    n1 = df.count()
    log.add("projects", "one row per normalised name", n0, n1, "Crawl was keyed by raw spelling, the analysis by PEP 503 name")

    # ---- Releases: one row per version, dated by its first uploaded file ------------------------------
    rel = (df.select("package", F.explode("releases").alias("version", "files"))
           .withColumn("n_files", F.size("files")))
    n2 = rel.count()
    rel_nofile = rel.filter(F.col("n_files") == 0)
    n3 = n2 - rel_nofile.count()
    rel = (rel.filter(F.col("n_files") > 0)
           .withColumn("upload_ts", F.array_min(F.transform(
               "files", lambda f: F.to_timestamp(F.substring(f["upload_time_iso_8601"], 1, 19), "yyyy-MM-dd'T'HH:mm:ss"))))
           .withColumn("yanked", F.forall("files", lambda f: F.coalesce(f["yanked"], F.lit(False))))
           .select("package", "version", "upload_ts", "n_files", "yanked"))
    log.add("releases", "version with no file", n2, n3, "A version with nothing to install has no upload date")
    rel_ok = rel.filter((F.col("upload_ts") >= PYPI_START) & (F.col("upload_ts") < SNAPSHOT_END))
    n4 = rel_ok.count()
    log.add("releases", "upload date outside PyPI's lifetime", n3, n4, "Impossible dates")
    rel_ok = write(rel_ok, "releases")

    stats = rel_ok.groupBy("package").agg(
        F.count("*").alias("n_releases"), F.min("upload_ts").alias("first_release"),
        F.max("upload_ts").alias("last_release"), F.collect_list("version").alias("all_versions"))
    projects = (df.select("package", F.col("info.version").alias("latest_version"),
                          F.col("info.yanked").alias("latest_yanked"), "last_serial",
                          F.coalesce(F.size("ownership.roles"), F.lit(0)).alias("n_maintainers"),
                          (F.col("ownership.organization").isNotNull()).alias("has_org"),
                          F.expr("transform(filter(vulnerabilities, v -> v.withdrawn IS NULL), v -> v.id)").alias("pypi_vuln_ids"),
                          F.col("info.requires_dist").alias("requires_dist"))
                .join(stats, "package", "left"))
    projects = write(projects, "projects")

    # ---- Dependencies --------------------------------------------------------------------------------
    parsed_type = StructType([StructField("dst", StringType()), StructField("spec", StringType()),
                              StructField("marker", StringType()), StructField("is_optional", BooleanType()),
                              StructField("is_conditional", BooleanType())])
    parse = F.udf(parse_requirement, parsed_type)

    lines = projects.select(F.col("package").alias("src"), F.explode("requires_dist").alias("req"))
    n5 = lines.count()
    # Many strings repeat ("numpy", "requests>=2"): parse each distinct one once.
    parsed = lines.select("req").distinct().withColumn("p", parse("req")).select("req", "p.*")
    deps = lines.join(parsed, "req")
    bad = deps.filter(F.col("dst").isNull()).count()
    deps = deps.filter(F.col("dst").isNotNull())
    log.add("dependencies", "requirement that does not parse", n5, n5 - bad, "Not valid PEP 508, target cannot be read")

    no_self = deps.filter(F.col("src") != F.col("dst"))
    n6 = no_self.count()
    log.add("dependencies", "self-dependency", n5 - bad, n6, "Extras that point back to the same project")

    # A pair can appear several times with different markers. A pair is 'required' if any line is.
    edges = no_self.groupBy("src", "dst").agg(
        F.min("is_optional").alias("is_optional"),
        F.min(F.when(F.col("is_optional"), True).otherwise(F.col("is_conditional"))).alias("is_conditional"),
        F.first(F.when(~F.col("is_optional"), F.col("spec")), ignorenulls=True).alias("required_spec"),
        F.first("spec").alias("any_spec"))
    edges = edges.withColumn("spec", F.coalesce("required_spec", "any_spec")).drop("required_spec", "any_spec")
    edges = write(edges, "dependencies")
    log.add("dependencies", "one row per dependent-dependency", n6, edges.count(),
            "Same pair repeated for different markers")
    return projects, edges


def main():
    spark = get_spark("02_clean")
    log = RowLog()
    clean_changelog(spark, log)
    clean_advisories(spark, log)
    clean_projects(spark, log)

    deps = spark.read.parquet(str(BRONZE / "depsdev"))
    n0 = deps.count()
    deps = deps.withColumn("package", norm_name("name")).dropDuplicates(["package"])
    ok = deps.filter(F.col("http_error").isNull()).drop("http_error", "name")
    write(ok, "depsdev")
    log.add("depsdev", "package unknown to deps.dev", n0, ok.count(), "Kept out of the validation only")
    spark.stop()


if __name__ == "__main__":
    main()
