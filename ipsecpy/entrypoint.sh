#!/bin/bash -eu

set -o pipefail

# Configure routing
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
iptables -A FORWARD -i eth1 -j ACCEPT
iptables -A FORWARD -i eth0 -j ACCEPT

unbuffer python3 -c 'import ipsecpy; ipsecpy.main()'
