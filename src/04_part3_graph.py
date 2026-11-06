"""Part 3 (Variety): which vulnerable packages carry the most systemic risk?

Runs before Part 2 because the stream's watchlist comes from this step's reach numbers.

Graph: a vertex per package, a directed edge dependent -> dependency for each required
(non-extra) line of the latest release. Combined with OSV flaws, this gives
reach, centrality, dependents who cannot escape a flaw, and a ranking whose
stability is tested under other scoring choices.
"""
import math
import os

import pandas as pd
from graphframes import GraphFrame
from pyspark.sql import functions as F
from pyspark.sql.types import ArrayType, StringType

from common import get_spark, save_csv
from config import ACTIVE_SINCE, DATA, GOLD, MIN_VERSIONS, RESULTS, SILVER
from depparse import allowed_versions

OUT = "part3/"
BATCH = int(os.environ.get("DPA_REACH_BATCH", 400))  # landmarks per shortest-path run: keeps memory bounded


def graph_members(spark, projects, flaws, required):
    """Whose dependencies count: maintained projects, packages named by OSV, and anything those rely on.

    Written as a rule on the data, not on what the crawl happened to fetch, so a project
    fetched before the crawl list was tightened cannot change the result.
    """
    events = spark.read.parquet(str(SILVER / "events"))
    maintained = (events.filter((F.col("action_type") == "new_release") & (F.col("event_ts") >= ACTIVE_SINCE))
                  .groupBy(F.col("name_norm").alias("member")).agg(F.countDistinct("version").alias("n"))
                  .filter(f"n >= {MIN_VERSIONS}").select("member"))
    named = flaws.select(F.col("package").alias("member")).distinct()
    on_pypi = projects.select(F.col("package").alias("member"))
    members = maintained.union(named).distinct().join(on_pypi, "member")
    # Follow dependencies until no new project joins.
    while True:
        members = members.localCheckpoint()
        reached = (required.join(members, F.col("src") == F.col("member"), "left_semi")
                   .select(F.col("dst").alias("member")).distinct().join(on_pypi, "member"))
        new = reached.join(members, "member", "left_anti").localCheckpoint()
        added = new.count()
        print(f"graph members: {members.count():,}, adding {added:,}", flush=True)
        if added == 0:
            return members
        members = members.union(new)


def build_graph(spark):
    projects = spark.read.parquet(str(SILVER / "projects"))
    deps = spark.read.parquet(str(SILVER / "dependencies"))
    flaws = spark.read.parquet(str(SILVER / "flaw_package"))
    status = spark.read.parquet(str(GOLD / "flaw_status"))

    # Only required lines: an extra is opt-in, so it says little about what most installs pull in.
    required = deps.filter("NOT is_optional").select("src", "dst", "spec", "is_conditional")
    edges = required.join(graph_members(spark, projects, flaws, required), F.col("src") == F.col("member"), "left_semi")

    live = projects.select(F.col("package").alias("id"), F.lit(True).alias("on_pypi"), "latest_version", "n_maintainers", "last_release")
    mentioned = edges.select(F.col("dst").alias("id")).union(edges.select(F.col("src").alias("id"))).distinct()
    malicious = flaws.filter("is_malicious").select(F.col("package").alias("id")).distinct().withColumn("flagged_malicious", F.lit(True))

    per_pkg = status.groupBy("package").agg(
        F.count("*").alias("n_flaws"),
        F.sum(F.col("is_open").cast("int")).alias("n_open"),
        F.max("severity").alias("max_severity"),
        F.max(F.when(F.col("is_open"), F.col("severity"))).alias("max_open_severity"),
        F.sum(F.when(F.col("is_open") & F.col("fixed_versions").isNotNull(), 1).otherwise(0)).alias("n_open_with_fix"),
    ).withColumnRenamed("package", "id")

    vertices = (mentioned.union(live.select("id")).distinct()
                .join(live, "id", "left").join(malicious, "id", "left").join(per_pkg, "id", "left")
                .na.fill({"on_pypi": False, "flagged_malicious": False, "n_flaws": 0, "n_open": 0, "n_open_with_fix": 0}))
    vertices.write.mode("overwrite").parquet(str(GOLD / "vertices"))
    edges.write.mode("overwrite").parquet(str(GOLD / "edges"))
    return spark.read.parquet(str(GOLD / "vertices")), spark.read.parquet(str(GOLD / "edges"))


def structure(g):
    """Basic shape, degree and centrality, written back as vertex columns."""
    in_deg = g.inDegrees.withColumnRenamed("inDegree", "direct_dependents")
    out_deg = g.outDegrees.withColumnRenamed("outDegree", "n_dependencies")
    # With edges pointing at dependencies, PageRank flows to what everything rests on.
    rank = g.pageRank(resetProbability=0.15, maxIter=10).vertices.select("id", F.col("pagerank"))
    comps = g.connectedComponents().select("id", "component")

    v = (g.vertices.join(in_deg, "id", "left").join(out_deg, "id", "left").join(rank, "id", "left").join(comps, "id", "left")
         .na.fill({"direct_dependents": 0, "n_dependencies": 0}))
    v.write.mode("overwrite").parquet(str(GOLD / "vertices_metrics"))
    return v.sparkSession.read.parquet(str(GOLD / "vertices_metrics"))


def shape_tables(v, e):
    n = v.count()
    m = e.count()
    largest = v.groupBy("component").count().agg(F.max("count")).first()[0]
    isolated = v.filter("direct_dependents = 0 AND n_dependencies = 0").count()
    total_in = v.agg(F.sum("direct_dependents")).first()[0]
    top = max(1, n // 100)
    top_share = v.orderBy(F.desc("direct_dependents")).limit(top).agg(F.sum("direct_dependents")).first()[0]
    rows = [("vertices", n), ("edges (required dependencies)", m),
            ("vertices on PyPI", v.filter("on_pypi").count()),
            ("names not on PyPI but required by someone", v.filter("NOT on_pypi AND direct_dependents > 0").count()),
            ("packages nobody requires", v.filter("direct_dependents = 0").count()),
            ("packages with no links at all", isolated),
            ("largest weakly connected component", largest),
            ("pct of vertices in the largest component", round(100 * largest / n, 1)),
            ("pct of dependency edges pointing at the top 1% of packages", round(100 * top_share / total_in, 1)),
            ("pct of edges limited by an environment marker", round(100 * e.filter("is_conditional").count() / m, 1))]
    save_csv(pd.DataFrame(rows, columns=["metric", "value"]), OUT + "graph_shape.csv")
    save_csv(v.groupBy(F.least("direct_dependents", F.lit(100000)).alias("direct_dependents")).count()
             .orderBy("direct_dependents"), OUT + "indegree_distribution.csv")
    print(pd.DataFrame(rows).to_string(index=False), flush=True)


def reach_of_vulnerable(spark, g, v):
    """Transitive dependents of each package with a flaw, by GraphFrames shortestPaths in batches."""
    path = GOLD / "reach"
    landmarks = [r.id for r in v.filter("n_flaws > 0 AND direct_dependents > 0").orderBy(F.desc("direct_dependents")).select("id").collect()]
    print(f"reach: {len(landmarks)} landmarks, batches of {BATCH}", flush=True)
    # Only vertices that can reach something matter: leaves of the dependency tree with no outgoing edge are dropped.
    sp = GraphFrame(v.filter("n_dependencies > 0 OR direct_dependents > 0").select("id"), g.edges.select("src", "dst")).cache()
    for i in range(0, len(landmarks), BATCH):
        batch = landmarks[i:i + BATCH]
        dist = sp.shortestPaths(landmarks=batch)
        out = (dist.select("id", F.explode("distances").alias("landmark", "hops"))
               .filter(F.col("id") != F.col("landmark"))
               .groupBy("landmark").agg(F.count("*").alias("reach"), F.max("hops").alias("max_depth"),
                                        F.round(F.avg("hops"), 3).alias("mean_depth")))
        out.write.mode("overwrite" if i == 0 else "append").parquet(str(path))
        print(f"reach: {min(i + BATCH, len(landmarks))}/{len(landmarks)}", flush=True)
    return spark.read.parquet(str(path)).withColumnRenamed("landmark", "id")


def locked_dependents(spark, g, v):
    """A dependent is locked when every release its version range allows carries the flaw."""
    status = spark.read.parquet(str(GOLD / "flaw_status")).filter("size(affected_versions) > 0") \
        .select(F.col("package").alias("dst"), "cluster_id", "severity", "is_open", "affected_versions")
    versions = spark.read.parquet(str(SILVER / "projects")).select(F.col("package").alias("dst"), "all_versions")
    specs = g.edges.select("dst", "spec").distinct().join(status.select("dst").distinct(), "dst").join(versions, "dst")
    allowed = F.udf(allowed_versions, ArrayType(StringType()))
    specs = specs.withColumn("allowed", allowed("spec", "all_versions")).drop("all_versions")
    # Test each distinct package, range and flaw once. Popular packages have thousands of dependents
    # and hundreds of flaws, so testing per dependency link would not fit in memory.
    locked_specs = (specs.filter("size(allowed) > 0").join(status, "dst")
                    .filter(F.size(F.array_except("allowed", "affected_versions")) == 0)
                    .select("dst", "spec", "cluster_id", "severity", "is_open"))
    locked_specs.write.mode("overwrite").parquet(str(DATA / "tmp_locked_specs"))
    locked_specs = spark.read.parquet(str(DATA / "tmp_locked_specs"))

    # The motif (x)-[e]->(p) with p flawed, then only the links whose range failed the test.
    motif = g.find("(x)-[e]->(p)").filter("p.n_flaws > 0") \
        .select(F.col("x.id").alias("src"), F.col("p.id").alias("dst"), F.col("e.spec").alias("spec"))
    locked = motif.join(locked_specs, ["dst", "spec"])
    locked.select("src", "dst", "cluster_id", "severity", "is_open").write.mode("overwrite").parquet(str(GOLD / "locked_edges"))
    locked = spark.read.parquet(str(GOLD / "locked_edges"))

    edges_into_flawed = motif.count()
    fixable = locked.filter("NOT is_open")
    serious = locked.filter("severity >= 7")
    rows = [("required links into a package that has any flaw", edges_into_flawed),
            ("of those, locked to at least one flaw", locked.select("src", "dst").distinct().count()),
            ("locked to a flaw the latest release has fixed", fixable.select("src", "dst").distinct().count()),
            ("dependents locked to at least one flaw", locked.select("src").distinct().count()),
            ("dependents locked to a flaw of severity 7 or more", serious.select("src").distinct().count()),
            ("dependents locked to a flaw the latest release has fixed", fixable.select("src").distinct().count())]
    print(save_csv(pd.DataFrame(rows, columns=["metric", "value"]), OUT + "locked_summary.csv").to_string(index=False), flush=True)

    per_pkg = locked.groupBy(F.col("dst").alias("id")).agg(
        F.countDistinct("src").alias("locked_dependents"),
        F.countDistinct(F.when(~F.col("is_open"), F.col("src"))).alias("locked_despite_fix_in_latest"))
    return per_pkg


def rank_tables(spark, v, reach, locked):
    t = v.filter("n_flaws > 0").join(reach, "id", "left").join(locked, "id", "left") \
        .na.fill({"reach": 0, "locked_dependents": 0, "locked_despite_fix_in_latest": 0}) \
        .join(spark.read.parquet(str(SILVER / "depsdev")).withColumnRenamed("package", "id")
              .select("id", "dependentCount", "directDependentCount"), "id", "left")
    pdf = t.select("id", "latest_version", "n_flaws", "n_open", "n_open_with_fix", "max_severity", "max_open_severity",
                   "direct_dependents", "reach", "max_depth", "mean_depth", "pagerank", "locked_dependents",
                   "locked_despite_fix_in_latest", "n_maintainers", "last_release", "dependentCount",
                   "directDependentCount").toPandas()

    # Severity is missing for a few flaws. The median keeps them neither first nor last.
    pdf["sev_any"] = pdf["max_severity"].fillna(pdf["max_severity"].median())
    pdf["sev_open"] = pdf["max_open_severity"].fillna(pdf["max_severity"]).fillna(pdf["max_severity"].median())
    pdf["log_reach"] = (pdf["reach"] + 1).map(math.log10)
    top = pdf["log_reach"].max() or 1
    pdf["risk_open"] = (pdf["sev_open"] / 10) * (pdf["log_reach"] / top) * (pdf["n_open"] > 0)
    pdf["risk_history"] = (pdf["sev_any"] / 10) * (pdf["log_reach"] / top)
    pdf = pdf.sort_values("risk_open", ascending=False)
    (RESULTS / OUT).mkdir(parents=True, exist_ok=True)

    cols = ["id", "latest_version", "n_open", "n_open_with_fix", "max_open_severity", "direct_dependents", "reach",
            "max_depth", "pagerank", "locked_dependents", "n_maintainers", "last_release", "dependentCount", "risk_open"]
    open_top = pdf[pdf["n_open"] > 0].head(50)[cols].round({"pagerank": 2, "risk_open": 3})
    save_csv(open_top, OUT + "top_open_risk.csv")
    cols_h = ["id", "n_flaws", "n_open", "max_severity", "direct_dependents", "reach", "pagerank", "locked_dependents",
              "locked_despite_fix_in_latest", "dependentCount", "risk_history"]
    hist_top = pdf.sort_values("risk_history", ascending=False).head(50)[cols_h].round({"pagerank": 2, "risk_history": 3})
    save_csv(hist_top, OUT + "top_history_risk.csv")
    save_csv(pdf.sort_values("locked_dependents", ascending=False).head(30)[
        ["id", "n_flaws", "n_open", "reach", "locked_dependents", "locked_despite_fix_in_latest"]], OUT + "top_locked.csv")
    pdf.to_parquet(GOLD / "ranking.parquet", index=False, coerce_timestamps="us", allow_truncated_timestamps=True)
    save_csv(pdf[["id", "n_flaws", "n_open", "max_severity", "max_open_severity", "direct_dependents", "reach", "max_depth",
                  "pagerank", "locked_dependents", "dependentCount", "directDependentCount", "risk_open", "risk_history"]]
             .round({"pagerank": 3, "risk_open": 4, "risk_history": 4}), OUT + "ranking_all.csv")
    print(open_top.head(25).to_string(index=False), flush=True)
    print(hist_top.head(25).to_string(index=False), flush=True)
    return pdf


def sensitivity(pdf):
    """Does the top of the ranking depend on how the score is built?"""
    d = pdf[pdf["n_open"] > 0].copy()
    log1 = lambda s: (s.fillna(0) + 1).map(math.log10)  # noqa: E731
    variants = {
        "reach x severity (baseline)": d["risk_open"],
        "reach only": log1(d["reach"]),
        "direct dependents x severity": log1(d["direct_dependents"]) * d["sev_open"],
        "pagerank x severity": log1(d["pagerank"]) * d["sev_open"],
        "reach x severity squared": log1(d["reach"]) * d["sev_open"] ** 2,
        "reach x number of open flaws": log1(d["reach"]) * d["n_open"],
        "deps.dev dependents x severity": log1(d["dependentCount"]) * d["sev_open"],
    }
    base = variants["reach x severity (baseline)"]
    top20 = set(base.nlargest(20).index)
    rows = []
    for name, score in variants.items():
        rows.append({"variant": name, "spearman_with_baseline": round(base.corr(score, method="spearman"), 3),
                     "top20_overlap": len(top20 & set(score.nlargest(20).index))})
    table = save_csv(pd.DataFrame(rows), OUT + "rank_sensitivity.csv")
    print(table.to_string(index=False), flush=True)

    known = pdf.dropna(subset=["dependentCount"])
    validation = pd.DataFrame([{
        "packages_compared": len(known),
        "spearman_reach_vs_depsdev_all": round(known["reach"].corr(known["dependentCount"], method="spearman"), 3),
        "spearman_direct_vs_depsdev_direct": round(known["direct_dependents"].corr(known["directDependentCount"], method="spearman"), 3),
        "top50_overlap": len(set(known.nlargest(50, "reach")["id"]) & set(known.nlargest(50, "dependentCount")["id"])),
        "median_reach": known["reach"].median(), "median_depsdev": known["dependentCount"].median(),
    }])
    print(save_csv(validation, OUT + "depsdev_validation.csv").to_string(index=False), flush=True)


def risky_links(v, g):
    """Required links to names that are flagged malicious or do not exist. Counts only:
    a public list of unregistered names people depend on would help the attackers."""
    motif = g.find("(x)-[e]->(p)").filter("x.on_pypi")
    mal = motif.filter("p.flagged_malicious")
    missing = motif.filter("NOT p.on_pypi AND NOT p.flagged_malicious")
    rows = [("required links to a name with a malicious-package advisory", mal.count()),
            ("distinct dependents behind those links", mal.select("x.id").distinct().count()),
            ("distinct flagged names so depended on", mal.select("p.id").distinct().count()),
            ("flagged names currently on PyPI", v.filter("flagged_malicious AND on_pypi").count()),
            ("required links to a name that returns 404 on PyPI", missing.count()),
            ("distinct dependents behind those links", missing.select("x.id").distinct().count()),
            ("distinct missing names", missing.select("p.id").distinct().count())]
    table = save_csv(pd.DataFrame(rows, columns=["metric", "value"]), OUT + "risky_links.csv")
    print(table.to_string(index=False), flush=True)


def main():
    spark = get_spark("04_part3", shuffle=32)
    spark.sparkContext.setCheckpointDir(str(DATA / "checkpoints"))
    v0, e = build_graph(spark)
    g0 = GraphFrame(v0, e)
    v = structure(g0)
    g = GraphFrame(v, e)
    shape_tables(v, e)
    risky_links(v, g)
    reach = reach_of_vulnerable(spark, g, v)
    locked = locked_dependents(spark, g, v)
    pdf = rank_tables(spark, v, reach, locked)
    sensitivity(pdf)
    spark.stop()


if __name__ == "__main__":
    main()
