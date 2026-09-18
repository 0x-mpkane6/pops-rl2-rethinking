FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential python3 python3-dev python3-pip python3-scapy \
    iptables iproute2 procps libnetfilter-queue1 libnetfilter-queue-dev \
    libnfnetlink0 libnfnetlink-dev tshark ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir NetfilterQueue
WORKDIR /app
COPY e5_lib.py /app/e5_lib.py
COPY routed_lab/wire.py /app/wire.py
COPY routed_lab/ips /app/ips
COPY routed_lab/ips/policy.py /app/policy.py
COPY routed_lab/ips/preflight.sh /app/preflight.sh
COPY routed_lab/ips/snapshot.sh /app/snapshot.sh
COPY routed_lab/ips/entrypoint.sh /app/entrypoint.sh
COPY routed_lab/ips/nfqueue_probe.py /app/nfqueue_probe.py
RUN find /app -type f -exec sed -i 's/\r$//' {} + \
    && chmod +x /app/*.sh /app/ips/*.sh \
    && mkdir -p /app/log /app/pcap
CMD ["/app/entrypoint.sh"]
