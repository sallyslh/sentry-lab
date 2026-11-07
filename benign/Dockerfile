FROM debian:12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl openssh-client sshpass \
    && rm -rf /var/lib/apt/lists/*

COPY benign.sh /benign.sh
RUN chmod +x /benign.sh

CMD ["/benign.sh"]
