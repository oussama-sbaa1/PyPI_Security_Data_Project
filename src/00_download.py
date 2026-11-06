"""Download every raw dataset. Standard library only, restartable at any point.

    python src/00_download.py osv          # OSV PyPI advisories (all.zip)
    python src/00_download.py changelog    # PyPI event log, one CSV per 1M serials
    python src/00_download.py projects     # PyPI project JSON for the active set
    python src/00_download.py closure      # same, for dependencies outside that set
    python src/00_download.py depsdev      # deps.dev dependent counts (validation)
    python src/00_download.py all

--sample keeps a few changelog parts and 2,000 projects, for a quick trial run.
Every finished file is recorded with its size in data/raw/MANIFEST.csv.
"""
import argparse
import csv
import gzip
import http.client
import json
import random
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xmlrpc.client
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from config import (ACTIVE_SINCE, CHANGELOG_END_SERIAL, DEPSDEV, OSV_URL, PART_SIZE,
                    PYPI_JSON, RAW, USER_AGENT, pypi_client)

MANIFEST_LOCK = threading.Lock()
TRANSIENT = (urllib.error.URLError, http.client.HTTPException, socket.timeout,
             ConnectionError, TimeoutError, xmlrpc.client.ProtocolError)


def log(*args):
    print(datetime.now().strftime("%H:%M:%S"), *args, flush=True)


def manifest(path, source, rows=""):
    """Record one finished file, so the report's sizes can be traced."""
    file = RAW / "MANIFEST.csv"
    with MANIFEST_LOCK:
        new = not file.exists()
        with open(file, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["file", "source", "bytes", "rows", "retrieved_utc"])
            w.writerow([path.relative_to(RAW).as_posix(), source, path.stat().st_size, rows,
                        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")])


def retry(fn, attempts=8):
    for i in range(attempts):
        try:
            return fn()
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or i == attempts - 1:
                raise
        except TRANSIENT:
            if i == attempts - 1:
                raise
        time.sleep(min(60, 2 ** i) + random.random())


def http_get(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# ---- OSV ------------------------------------------------------------------
def osv():
    out = RAW / "osv" / "all.zip"
    if out.exists():
        log("osv: already there")
    else:
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_suffix(".part")
        tmp.write_bytes(retry(lambda: http_get(OSV_URL, 600)))
        tmp.rename(out)
        manifest(out, OSV_URL)
    # Spark reads one JSON record per line, so the zip of small files becomes one file.
    lines = RAW / "osv" / "osv_pypi.jsonl"
    if not lines.exists():
        n = 0
        tmp = lines.with_suffix(".part")
        with zipfile.ZipFile(out) as z, open(tmp, "w", encoding="utf-8") as f:
            for name in z.namelist():
                if name.endswith(".json"):
                    f.write(json.dumps(json.loads(z.read(name)), ensure_ascii=False) + "\n")
                    n += 1
        tmp.rename(lines)
        manifest(lines, "unzipped from all.zip", n)
        log("osv:", n, "records")


# ---- PyPI changelog --------------------------------------------------------
def fetch_part(part, end_serial):
    """Fetch serials [part*PART_SIZE, (part+1)*PART_SIZE) into one CSV."""
    out = RAW / "changelog" / f"changelog_{part:04d}.csv"
    if out.exists():
        return
    client = pypi_client()
    since = max(part * PART_SIZE - 1, 0)
    stop = min((part + 1) * PART_SIZE - 1, end_serial)
    tmp = out.with_suffix(".part")
    rows = 0
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["name", "version", "timestamp", "action", "serial"])
        while since < stop:
            batch = retry(lambda: client.changelog_since_serial(since))
            if not batch:
                break
            for name, version, ts, action, serial in batch:
                if serial > stop:
                    break
                # Each event must stay on one CSV line.
                w.writerow([name, version, ts, re.sub(r"[\r\n]+", " ", action or ""), serial])
                rows += 1
            since = batch[-1][4]
    tmp.rename(out)
    manifest(out, "pypi xml-rpc changelog_since_serial", rows)
    log(f"changelog part {part}: {rows:,} events")


def changelog(sample):
    (RAW / "changelog").mkdir(parents=True, exist_ok=True)
    last = CHANGELOG_END_SERIAL // PART_SIZE
    parts = list(range(last - 2, last + 1)) if sample else list(range(last + 1))
    with ThreadPoolExecutor(3) as pool:   # three connections: this API is not built for more
        list(pool.map(lambda p: fetch_part(p, CHANGELOG_END_SERIAL), parts))


def active_projects():
    """Maintained projects, plus every OSV package.

    Maintained: at least two versions released since ACTIVE_SINCE, and not deleted after the last one.
    This leaves out most one-off uploads. Anything a maintained project depends on still
    comes in through the closure step, so no dependency chain is cut.
    """
    since = int(datetime.fromisoformat(ACTIVE_SINCE).replace(tzinfo=timezone.utc).timestamp())
    first_version, several, last_release, last_removed = {}, set(), {}, {}
    for path in sorted((RAW / "changelog").glob("changelog_*.csv")):
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                ts = int(row["timestamp"])
                if ts < since:
                    continue
                name, action = row["name"], row["action"]
                if action == "new release":
                    last_release[name] = ts
                    if first_version.setdefault(name, row["version"]) != row["version"]:
                        several.add(name)
                elif action == "remove project" or (action == "remove" and not row["version"]):
                    last_removed[name] = ts
    maintained = {n for n in several if last_removed.get(n, 0) <= last_release[n]}
    log(f"projects: {len(last_release):,} released something since {ACTIVE_SINCE}, {len(maintained):,} are maintained")
    return maintained | osv_packages(include_malicious=True)


def osv_packages(include_malicious):
    names = set()
    with open(RAW / "osv" / "osv_pypi.jsonl", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            if not include_malicious and rec["id"].startswith("MAL-"):
                continue
            for a in rec.get("affected", []):
                if a.get("package", {}).get("ecosystem") == "PyPI":
                    names.add(a["package"]["name"])
    return names


# ---- PyPI project JSON -----------------------------------------------------
class Shards:
    """Thread-safe gzip JSONL writer. A part only counts once it is closed."""
    ROTATE = 20_000

    def __init__(self, folder):
        self.folder = folder
        folder.mkdir(parents=True, exist_ok=True)
        self.done_file = folder / "_done.txt"
        self.done = set(self.done_file.read_text(encoding="utf-8").split()) if self.done_file.exists() else set()
        self.seq = max([int(p.name.split("-")[1].split(".")[0]) for p in folder.glob("part-*.jsonl.gz")] + [-1]) + 1
        self.lock = threading.Lock()
        for stale in folder.glob("*.tmp"):
            stale.unlink()
        self._open()

    def _open(self):
        self.path = self.folder / f"part-{self.seq:05d}.jsonl.gz"
        self.tmp = self.path.with_name(self.path.name + ".tmp")
        self.gz = gzip.open(self.tmp, "wt", encoding="utf-8", compresslevel=6)
        self.names, self.pending = [], []

    def _close(self):
        self.gz.close()
        if self.names:
            self.tmp.rename(self.path)
            manifest(self.path, "pypi project json", len(self.names))
        else:
            self.tmp.unlink()
        with open(self.done_file, "a", encoding="utf-8") as f:
            f.writelines(n + "\n" for n in self.names + self.pending)
        self.seq += 1

    def add(self, name, line):
        with self.lock:
            self.gz.write(line + "\n")
            self.names.append(name)
            if len(self.names) >= self.ROTATE:
                self._close()
                self._open()

    def missing(self, name):
        with self.lock:
            self.pending.append(name)

    def close(self):
        with self.lock:
            self._close()


def fetch_project(name, shards, missing_log, counter):
    url = PYPI_JSON.format(name=urllib.parse.quote(name, safe=""))
    try:
        doc = json.loads(retry(lambda: http_get(url, 60)))
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        missing_log.write(name + "\n")
        missing_log.flush()
        shards.missing(name)
        return
    # Long descriptions and the 'urls' copy of the latest release are never used
    # and take most of the space, so they are dropped at the door.
    doc.pop("urls", None)
    doc["info"].pop("description", None)
    for files in doc.get("releases", {}).values():
        for file in files:
            for key in ("digests", "md5_digest", "comment_text", "url", "downloads", "has_sig"):
                file.pop(key, None)
    shards.add(name, json.dumps({"requested_name": name, **doc}, ensure_ascii=False))
    with counter["lock"]:
        counter["n"] += 1
        if counter["n"] % 10_000 == 0:
            log(f"projects: {counter['n']:,} fetched")


def crawl(names, sample):
    folder = RAW / "projects"
    shards = Shards(folder)
    todo = sorted(names - shards.done)
    if sample:  # a seeded random subset, so the trial run is repeatable
        todo = sorted(random.Random(42).sample(todo, min(2000, len(todo))))
    log(f"projects: {len(shards.done):,} done, {len(todo):,} to fetch")
    counter = {"n": 0, "lock": threading.Lock()}
    errors = 0
    # Eight connections: PyPI asks API clients to spread heavy use over time, so this is slow on purpose.
    with open(folder / "_missing.txt", "a", encoding="utf-8") as missing_log, ThreadPoolExecutor(8) as pool:
        futures = [pool.submit(fetch_project, n, shards, missing_log, counter) for n in todo]
        for fut in futures:
            try:
                fut.result()
            except Exception as e:  # one bad project must not stop a two-hour crawl
                errors += 1
                log("project failed:", repr(e)[:200])
    shards.close()
    log(f"projects: finished, {errors} errors (re-run to retry them)")


def required_names(path):
    """Required dependencies named in one part file, normalised. Extras are opt-in, so not followed."""
    token = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
    names = set()
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            for req in (json.loads(line)["info"].get("requires_dist") or []):
                m = token.match(req)
                if m and "extra" not in req.partition(";")[2]:
                    names.add(re.sub(r"[-_.]+", "-", m.group(1)).lower())
    return names


def closure(sample, max_rounds=8):
    """Fetch what the crawled projects require, then what those require, until nothing new appears."""
    folder = RAW / "projects"
    scanned, required = set(), set()
    for round_no in range(1, max_rounds + 1):
        for path in sorted(folder.glob("part-*.jsonl.gz")):
            if path.name not in scanned:
                required |= required_names(path)
                scanned.add(path.name)
        done = (folder / "_done.txt").read_text(encoding="utf-8").split()
        todo = required - {re.sub(r"[-_.]+", "-", n).lower() for n in done}
        log(f"closure round {round_no}: {len(required):,} required names, {len(todo):,} not fetched yet")
        if not todo:
            return
        crawl(todo, sample)
        if sample:
            return


# ---- deps.dev --------------------------------------------------------------
def fetch_depsdev(name):
    q = urllib.parse.quote(name, safe="")
    pkg = json.loads(retry(lambda: http_get(f"{DEPSDEV}/v3/systems/pypi/packages/{q}", 60)))
    default = next((v["versionKey"]["version"] for v in pkg["versions"] if v.get("isDefault")), None)
    rec = {"name": name, "default_version": default, "version_count": len(pkg["versions"])}
    if default:
        v = urllib.parse.quote(default, safe="")
        url = f"{DEPSDEV}/v3alpha/systems/pypi/packages/{q}/versions/{v}:dependents"
        rec.update(json.loads(retry(lambda: http_get(url, 60))))
    return rec


def depsdev(sample):
    out = RAW / "depsdev" / "pypi_dependents.jsonl"
    if out.exists():
        log("depsdev: already there")
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    names = sorted(osv_packages(include_malicious=False))
    names = names[:100] if sample else names

    def safe(name):
        try:
            return fetch_depsdev(name)
        except urllib.error.HTTPError as e:
            return {"name": name, "http_error": e.code}

    tmp = out.with_suffix(".part")
    rows = 0
    with ThreadPoolExecutor(6) as pool, open(tmp, "w", encoding="utf-8") as f:
        for rec in pool.map(safe, names):
            f.write(json.dumps(rec) + "\n")
            rows += 1
    tmp.rename(out)
    manifest(out, "deps.dev api", rows)
    log(f"depsdev: {rows} packages")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", choices=["osv", "changelog", "projects", "closure", "depsdev", "all"])
    ap.add_argument("--sample", action="store_true")
    args = ap.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)
    if args.step in ("osv", "all"):
        osv()
    if args.step in ("changelog", "all"):
        changelog(args.sample)
    if args.step in ("projects", "all"):
        crawl(active_projects(), args.sample)
    if args.step in ("closure", "all"):
        closure(args.sample)
    if args.step in ("depsdev", "all"):
        depsdev(args.sample)


if __name__ == "__main__":
    main()
