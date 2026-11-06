#!/usr/bin/env bash
# Everything after the download, in order. Run inside the container:
#   docker compose run --rm spark bash run_pipeline.sh
set -euo pipefail

python tests/test_helpers.py
python src/01_ingest.py
python src/02_clean.py
python src/03_part1_volume.py
python src/04_part3_graph.py      # before Part 2: the stream's watchlist comes from it
python src/05_part2_prepare.py
python src/06_part2_stream.py replay
python src/06_part2_stream.py watermarks
python src/06_part2_stream.py live --minutes 30
python src/07_part2_evaluate.py
python src/08_figures.py
