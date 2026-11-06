# Data sources

Nothing here is committed to the repository except small result tables: `src/00_download.py` fetches every raw file. Exact sizes and retrieval times of the run reported here are in `results/raw_manifest_summary.csv`.

| Dataset | Used in | Access | Licence or terms |
|---|---|---|---|
| [OSV PyPI advisories](https://google.github.io/osv.dev/data/) (`all.zip`) | Parts 1, 2, 3 | Public HTTP, no account | GHSA and PYSEC records: CC-BY 4.0. MAL records (from [ossf/malicious-packages](https://github.com/ossf/malicious-packages)): Apache-2.0 |
| [PyPI changelog](https://docs.pypi.org/api/) (XML-RPC `changelog_since_serial`) | Parts 1, 2 | Public API, no account | [PyPI Terms of Service](https://policies.python.org/pypi.org/Terms-of-Service/). Not redistributed; only aggregates are published |
| [PyPI project JSON](https://docs.pypi.org/api/json/) (`/pypi/<name>/json`) | Parts 1, 3 | Public API, no account | As above. Package names and version-level facts appear in results; maintainer names do not |
| [deps.dev API](https://docs.deps.dev/api/v3/) (dependent counts) | Validation of Part 3 | Public API, no account | CC-BY 4.0 |

Attribution: advisory data by the [GitHub Advisory Database](https://github.com/github/advisory-database), the [PyPA Advisory Database](https://github.com/pypa/advisory-database) and [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages), via [OSV.dev](https://osv.dev). Dependency counts by [deps.dev](https://deps.dev). None of them endorses this work.

## Being a polite client

PyPI's [API policies](https://docs.pypi.org/api/) ask heavy users to identify themselves and spread requests over time. So the download script:

- sends a `User-Agent` naming this project, with a link to this repository;
- uses at most 3 connections to XML-RPC and 8 to the JSON API;
- retries with exponential backoff on `429` and `5xx`;
- can stop and resume at any point, so nothing is ever fetched twice.

That makes the metadata crawl slow, about 6 hours. `--sample` gives a small, repeatable trial run instead.

## What the crawl covers

Metadata is fetched for three groups, in this order:

1. **maintained projects**: at least two different versions released since 2024-01-01, and not deleted after the last one;
2. every package named by an OSV record, whatever its activity;
3. whatever those projects require, then whatever that requires, until nothing new appears (`closure` step).

The rule leaves out one-off uploads and anything abandoned before 2024, unless something else in the graph depends on it. So reach numbers count *recently maintained* dependents, not everything ever published. `04_part3_graph.py` applies the same rule to the data itself, so the result does not depend on the order of the crawl.

Long descriptions, the per-file digests and the `urls` copy of the latest release are dropped as the JSON arrives. They are never used and take most of the space.

## Identity across sources

All four sources are joined on the [PEP 503](https://peps.python.org/pep-0503/) normalised project name: lower case, with runs of `-`, `_` and `.` replaced by a single `-`.
