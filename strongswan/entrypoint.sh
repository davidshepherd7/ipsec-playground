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
    # This is what is actually used to decide the DPD timeout for ikev2 (but
    # with exponential backoff, 5 retries, and jitter)
    # retransmit_timeout=2.0

conn ikev2-vpn
    # Simple proposals for testing parser
    # esp=aes128-sha256!
    # ike=aes128-sha256-modp3072
    ike=aes128-aes256-sha1-modp3072-modp2048,3des-sha1-md5-modp1024!

    auto=start
    type=tunnel
    authby=psk
    keyexchange=ikev2
    # fragmentation=yes
    # forceencaps=yes

    # This doesn't affect authentication failures, you have to retry those manually.
    keyingtries=%forever

    dpdaction=restart
    # How often we send a dpd request if there's no traffic (but, this seems to
    # only mean the control traffic: running lots of pings and it still sends the dpd
    # requests).
    dpddelay=5s

    rekey=yes
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
