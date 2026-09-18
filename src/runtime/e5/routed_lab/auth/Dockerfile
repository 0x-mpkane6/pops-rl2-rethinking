FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-scapy python3-dnslib iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY e5_lib.py /app/e5_lib.py
COPY routed_lab/wire.py /app/wire.py
COPY routed_lab/auth/auth_server.py /app/auth_server.py
COPY routed_lab/auth/entrypoint.sh /app/entrypoint.sh
RUN sed -i 's/\r$//' /app/*.py /app/*.sh && chmod +x /app/entrypoint.sh
CMD ["/app/entrypoint.sh"]
