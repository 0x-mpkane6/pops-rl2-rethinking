FROM ubuntu:22.04

RUN apt update && apt install -y \
    python3 \
    python3-pip \
    dnsutils \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir dnslib==0.9.26

WORKDIR /app
COPY resolver.py /app/resolver.py
COPY toggle_defense.sh /app/toggle_defense.sh
RUN chmod +x /app/toggle_defense.sh

CMD ["python3", "/app/resolver.py"]
