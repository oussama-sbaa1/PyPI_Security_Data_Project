"""Paths and snapshot constants shared by every step of the pipeline."""
import os
import xmlrpc.client
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("DPA_DATA", ROOT / "data"))
RAW = DATA / "raw"
BRONZE = DATA / "bronze"
SILVER = DATA / "silver"
GOLD = DATA / "gold"
# A trial run on another data folder (DPA_DATA=data/sample) must not overwrite the real results.
RESULTS = DATA / "results" if "DPA_DATA" in os.environ else ROOT / "results"
FIGURES = DATA / "figures" if "DPA_DATA" in os.environ else ROOT / "report" / "figures"

# ---- Snapshot -------------------------------------------------------------
# The changelog is cut at a fixed serial so a re-run sees the same events.
CHANGELOG_END_SERIAL = 43_308_081        # 2026-11-06
PART_SIZE = 1_000_000                    # serials per raw CSV part

# Project metadata is crawled for maintained projects (at least MIN_VERSIONS versions since this date),
# for every package named in OSV, then for whatever those projects depend on.
ACTIVE_SINCE = "2024-01-01"
MIN_VERSIONS = 2

OSV_URL = "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip"
PYPI_XMLRPC = "https://pypi.org/pypi"
PYPI_JSON = "https://pypi.org/pypi/{name}/json"
DEPSDEV = "https://api.deps.dev"
USER_AGENT = "dpa-pypi-security-study/1.0 (+https://github.com/oussama-sbaa1/PyPI_Security_Data_Project)"


class _Transport(xmlrpc.client.SafeTransport):
    user_agent = USER_AGENT     # PyPI asks heavy API users to identify themselves


def pypi_client():
    return xmlrpc.client.ServerProxy(PYPI_XMLRPC, transport=_Transport())
