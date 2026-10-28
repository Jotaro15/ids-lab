FROM nginx:1.27-alpine3.20

# Alpine drops old package versions from its repositories, so pinning them would
# break rebuilds. The base image tag is pinned instead.
# The pipe only feeds chpasswd, whose exit status is the one that matters.
# hadolint ignore=DL3018,DL4006
RUN apk add --no-cache openssh-server \
    && ssh-keygen -A \
    && adduser -D -s /bin/sh labuser \
    && echo "labuser:sunshine" | chpasswd

COPY docker/victim/sshd_config /etc/ssh/sshd_config
COPY docker/victim/index.html /usr/share/nginx/html/index.html
# The official nginx entrypoint runs every executable script in this folder
# before starting nginx.
COPY docker/victim/start-sshd.sh /docker-entrypoint.d/40-sshd.sh
RUN chmod 755 /docker-entrypoint.d/40-sshd.sh

EXPOSE 22 80

HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD wget -q --spider http://127.0.0.1/ || exit 1
