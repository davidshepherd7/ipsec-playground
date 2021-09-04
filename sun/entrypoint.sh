#!/bin/bash -eu

set -o pipefail


iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
iptables -A FORWARD -i eth1 -j ACCEPT
iptables -A FORWARD -i eth0 -j ACCEPT
# ip route add 172.28.0.0/16 via 172.30.0.2

cat << EOF > /etc/ipsec.secrets
: PSK HELLOWORLD
EOF

unbuffer ipsec start --nofork --debug-all
