FROM python:3.12-slim-bookworm

# Debian's package index moves under us between builds, so pinning exact
# package versions here would break rebuilds within days of release. The
# base image tag is pinned instead, and apt-get update always runs right
# before installing.
# hadolint ignore=DL3008,DL3009
RUN apt-get update \
    && apt-get install --no-install-recommends -y nmap hping3 hydra \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --root-user-action=ignore .

WORKDIR /work
