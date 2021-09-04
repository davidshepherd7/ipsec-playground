#!/bin/bash -eu

set -o pipefail

# ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca-key.pem


/usr/sbin/ipsec start --nofork
