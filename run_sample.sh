#!/usr/bin/env bash
# A short end-to-end trial on a small, repeatable sample: about 25 minutes.
# Run inside the container:  docker compose run --rm spark bash run_sample.sh
# Everything goes to data/sample, so it can never overwrite the real results.
set -eo pipefail
export DPA_DATA=data/sample

python tests/test_helpers.py
python src/00_download.py all --sample
python src/01_ingest.py
python src/02_clean.py
python src/03_part1_volume.py
python src/04_part3_graph.py
# The sample's changelog only covers the last few weeks of the snapshot.
python src/05_part2_prepare.py --start 2026-09-20 --slice-start 2026-10-01 --slice-days 3
python src/06_part2_stream.py replay --pace 0.3
python src/06_part2_stream.py watermarks --wm-pace 0.3 --watermarks "10 minutes,48 hours"
python src/06_part2_stream.py live --minutes 2
python src/07_part2_evaluate.py
python src/08_figures.py
echo "Sample run finished: see data/sample/results and data/sample/figures"
