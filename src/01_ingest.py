"""Raw files -> typed Parquet (bronze). Explicit schemas, nothing is cleaned here."""
import pandas as pd
from pyspark.sql import functions as F
from pyspark.sql.types import (ArrayType, BooleanType, LongType, MapType, StringType, StructField,
                               StructType)

from common import get_spark, save_csv
from config import BRONZE, RAW


def s(name, kind=None):
    return StructField(name, kind or StringType())


CHANGELOG = StructType([s("name"), s("version"), s("timestamp", LongType()), s("action"),
                        s("serial", LongType()), s("_corrupt")])

OSV = StructType([
    s("id"), s("published"), s("modified"), s("withdrawn"), s("summary"),
    s("aliases", ArrayType(StringType())),
    s("severity", ArrayType(StructType([s("type"), s("score")]))),
    s("database_specific", StructType([s("severity"), s("github_reviewed", BooleanType()),
                                       s("nvd_published_at"), s("cwe_ids", ArrayType(StringType()))])),
    s("affected", ArrayType(StructType([
        s("package", StructType([s("name"), s("ecosystem")])),
        s("versions", ArrayType(StringType())),
        s("ranges", ArrayType(StructType([
            s("type"),
            s("events", ArrayType(StructType([s("introduced"), s("fixed"), s("last_affected"), s("limit")]))),
        ]))),
    ]))),
])

PROJECT = StructType([
    s("requested_name"), s("last_serial", LongType()),
    s("info", StructType([
        s("name"), s("version"), s("requires_python"), s("license_expression"), s("yanked", BooleanType()),
        s("requires_dist", ArrayType(StringType())),
    ])),
    s("ownership", StructType([s("organization"), s("roles", ArrayType(StructType([s("role"), s("user")])))])),
    s("vulnerabilities", ArrayType(StructType([
        s("id"), s("withdrawn"), s("aliases", ArrayType(StringType())), s("fixed_in", ArrayType(StringType())),
    ]))),
    s("releases", MapType(StringType(), ArrayType(StructType([
        s("upload_time_iso_8601"), s("packagetype"), s("size", LongType()), s("yanked", BooleanType()),
    ])))),
])

DEPSDEV = StructType([
    s("name"), s("default_version"), s("version_count", LongType()), s("http_error", LongType()),
    s("dependentCount", LongType()), s("directDependentCount", LongType()), s("indirectDependentCount", LongType()),
])


def main():
    spark = get_spark("01_ingest")
    counts = []

    changelog = (spark.read.schema(CHANGELOG)
                 .option("header", True).option("escape", '"').option("mode", "PERMISSIVE")
                 # 30 old version strings contain a line break, inside a quoted field. Without this option
                 # each one splits into two corrupt rows.
                 .option("multiLine", True)
                 .option("columnNameOfCorruptRecord", "_corrupt")
                 .csv(str(RAW / "changelog" / "changelog_*.csv")))
    # The corrupt-record column goes to Parquet too: Spark refuses to count it on the raw CSV alone,
    # and caching 43 million rows just for that count would not fit in memory.
    changelog.repartition(48).write.mode("overwrite").parquet(str(BRONZE / "changelog"))
    typed = spark.read.parquet(str(BRONZE / "changelog"))
    counts.append(("changelog", typed.count(), typed.filter(F.col("_corrupt").isNotNull()).count()))

    osv = spark.read.schema(OSV).json(str(RAW / "osv" / "osv_pypi.jsonl"))
    osv.write.mode("overwrite").parquet(str(BRONZE / "osv"))
    counts.append(("osv", spark.read.parquet(str(BRONZE / "osv")).count(), 0))

    projects = spark.read.schema(PROJECT).json(str(RAW / "projects" / "part-*.jsonl.gz"))
    projects.write.mode("overwrite").parquet(str(BRONZE / "projects"))
    counts.append(("projects", spark.read.parquet(str(BRONZE / "projects")).count(), 0))

    deps = spark.read.schema(DEPSDEV).json(str(RAW / "depsdev" / "pypi_dependents.jsonl"))
    deps.write.mode("overwrite").parquet(str(BRONZE / "depsdev"))
    counts.append(("depsdev", spark.read.parquet(str(BRONZE / "depsdev")).count(), 0))

    table = spark.createDataFrame(counts, ["table", "rows", "corrupt_rows"])
    table.show(truncate=False)
    save_csv(table, "ingest_counts.csv")

    # What was downloaded, for the report's size table. The manifest itself stays with the data.
    files = pd.read_csv(RAW / "MANIFEST.csv")
    files["dataset"] = files["file"].str.split("/").str[0]
    sizes = files.groupby("dataset").agg(files=("file", "count"), bytes=("bytes", "sum"), rows=("rows", "sum"),
                                         first_retrieved=("retrieved_utc", "min"), last_retrieved=("retrieved_utc", "max")).reset_index()
    sizes["gb"] = (sizes["bytes"] / 1e9).round(3)
    print(save_csv(sizes, "raw_manifest_summary.csv").to_string(index=False), flush=True)
    spark.stop()


if __name__ == "__main__":
    main()
