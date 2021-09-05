FROM ubuntu-with-tools

RUN apt-get update \
    && apt-get install -y python3 iptables expect

COPY ./ipsecpy/ /ipsecpy/
COPY ./entrypoint.sh /

CMD /entrypoint.sh
