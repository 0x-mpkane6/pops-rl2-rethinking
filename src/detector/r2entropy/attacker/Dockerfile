FROM kalilinux/kali-rolling

RUN apt update && apt install -y \
    dnsutils python3 python3-scapy tcpdump iproute2 net-tools

WORKDIR /app
COPY scripts/ /app/
RUN chmod +x /app/*.py

CMD ["sleep", "infinity"]
