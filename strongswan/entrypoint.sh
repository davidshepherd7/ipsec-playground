#!/bin/bash -eu

set -o pipefail

# Configure routing
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
iptables -A FORWARD -i eth1 -j ACCEPT
iptables -A FORWARD -i eth0 -j ACCEPT

# Configure pre-shared key
cat << EOF > /etc/ipsec.secrets
: PSK $PSK
EOF

# Configure the connection
cat <<EOF > /etc/ipsec.conf
# Goes in /etc/ipsec.conf
#
# https://wiki.strongswan.org/projects/strongswan/wiki/connsection

config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn ikev2-vpn
    auto=start
    type=tunnel
    authby=psk
    keyexchange=ikev2
    # fragmentation=yes
    # forceencaps=yes

    dpdaction=restart
    dpddelay=30s
    dpdtimeout=10s
    rekey=no
    closeaction=restart

    left=%any
    leftsubnet=$LOCAL_SUBNET
    leftauth=psk

    right=$REMOTE_IP
    rightsubnet=$REMOTE_SUBNET
    rightauth=psk
EOF

# Launch the daemon
unbuffer ipsec start --nofork --debug-all
