FROM ubuntu:22.04
RUN apt update && apt install -y dnsutils gawk && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY test.sh /app/
RUN chmod +x /app/test.sh
CMD ["sleep", "infinity"]
