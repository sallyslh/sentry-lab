FROM debian:12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx openssh-server iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && useradd -m -s /bin/bash labuser \
    && echo 'labuser:labpass123' | chpasswd

COPY index.html /var/www/html/index.html
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 22
CMD ["/entrypoint.sh"]
