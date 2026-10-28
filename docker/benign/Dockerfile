FROM python:3.12-alpine3.20

# Alpine drops old package versions from its repositories, so pinning them would
# break rebuilds. The base image tag is pinned instead.
# hadolint ignore=DL3018
RUN apk add --no-cache openssh-client sshpass \
    && adduser -D -s /sbin/nologin benign

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# The generator only uses the standard library, so one file is enough.
COPY src/idslab/lab/benign.py /app/benign.py

USER benign
ENTRYPOINT ["python", "/app/benign.py"]
