# Same base image as the course TPs, pinned to an exact version: Spark 3.5.0, Python 3.11.
FROM jupyter/pyspark-notebook:spark-3.5.0

USER root

# GraphFrames for Part 3, baked in so that runs need no network. The jar also holds the Python module.
RUN curl -fsSL --retry 5 --retry-all-errors -o /usr/local/spark/jars/graphframes-0.8.3-spark3.5-s_2.12.jar \
    https://repos.spark-packages.org/graphframes/graphframes/0.8.3-spark3.5-s_2.12/graphframes-0.8.3-spark3.5-s_2.12.jar
ENV PYTHONPATH=/usr/local/spark/python:/usr/local/spark/python/lib/py4j-0.10.9.7-src.zip:/usr/local/spark/jars/graphframes-0.8.3-spark3.5-s_2.12.jar:/home/jovyan/project/src

# PEP 508 parsing of dependency strings and PEP 440 version ranges.
RUN pip install --no-cache-dir packaging==24.2

# Spark's scratch and streaming state live in a Docker volume, see compose.yaml.
RUN mkdir -p /tmp/spark && chown -R ${NB_UID}:${NB_GID} /tmp/spark

USER ${NB_UID}

# The project is mounted by compose.yaml, so data and results stay on the host.
WORKDIR /home/jovyan/project
