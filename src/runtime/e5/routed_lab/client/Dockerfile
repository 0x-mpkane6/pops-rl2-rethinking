FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 dnsutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY tools/routed_lab/client/probe.py /app/probe.py
RUN sed -i 's/\r$//' /app/probe.py
CMD ["sleep", "infinity"]
