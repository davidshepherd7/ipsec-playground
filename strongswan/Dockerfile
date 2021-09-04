FROM ubuntu:latest
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y strongswan strongswan-pki iptables \
    iproute2 inetutils-ping curl host mtr-tiny tcpdump \
    && rm -rf /var/lib/apt/lists/*

ADD entrypoint.sh /

ENTRYPOINT /entrypoint.sh
