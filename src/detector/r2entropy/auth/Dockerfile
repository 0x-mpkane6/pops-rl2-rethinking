FROM ubuntu:22.04

RUN apt update && apt install -y \
    python3 \
    python3-pip \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir dnslib==0.9.26

WORKDIR /app
COPY auth_server.py /app/auth_server.py
COPY toggle_benign_frag2.sh /app/toggle_benign_frag2.sh
RUN chmod +x /app/toggle_benign_frag2.sh

CMD ["python3", "/app/auth_server.py"]
