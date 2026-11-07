FROM kalilinux/kali-rolling

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        hping3 \
        python3-scapy \
        hydra \
        netcat-traditional \
        iputils-ping \
        iproute2 \
        openssh-client \
        sshpass \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /scripts
CMD ["sleep", "infinity"]
