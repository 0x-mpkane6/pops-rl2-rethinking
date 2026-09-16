# syntax=docker/dockerfile:1
FROM ubuntu:22.04 AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential flex bison swig libssl-dev libexpat1-dev libevent-dev \
    python3 python3-dev python3-distutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=unbound_src . /src/unbound
WORKDIR /src/unbound
RUN find . -type f \( -name '*.c' -o -name '*.h' -o -name '*.in' -o -name '*.ac' -o -name '*.m4' -o -name '*.py' -o -name '*.sh' -o -name '*.awk' -o -name '*.i' -o -name 'configure' -o -name 'config.*' -o -name 'Makefile*' -o -name 'install-sh' -o -name 'ltmain.sh' \) -exec sed -i 's/\r$//' {} +
RUN ln -sf /usr/bin/python3 /usr/bin/python \
    && PYTHON_VERSION=3 ./configure --prefix=/usr --sysconfdir=/etc --with-libevent --with-pythonmodule --disable-rpath \
    && make -j"$(nproc)" \
    && make install DESTDIR=/opt/unbound-root

FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-scapy libssl3 libexpat1 libevent-2.1-7 libpython3.10 \
    iproute2 dnsutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/unbound-root/usr /usr
RUN ldconfig && mkdir -p /etc/unbound /app /app/log && unbound -V
COPY tools/routed_lab/resolver/unbound.conf /etc/unbound/unbound.conf
COPY tools/routed_lab/resolver/e5mod.py /etc/unbound/e5mod.py
COPY tools/routed_lab/resolver/cache_probe.py /app/cache_probe.py
COPY tools/routed_lab/resolver/start.sh /app/start.sh
RUN sed -i 's/\r$//' /app/*.py /app/*.sh /etc/unbound/*.conf /etc/unbound/*.py \
    && chmod +x /app/start.sh \
    && unbound-checkconf /etc/unbound/unbound.conf
WORKDIR /app
CMD ["/app/start.sh"]
