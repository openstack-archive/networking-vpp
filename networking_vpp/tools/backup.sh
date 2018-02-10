#!/bin/sh

# This script is used by keepalived to notify the vpp-agent
# when the VRRP router state transitions to BACKUP.
# Hostname of the network node is the required argument
HOSTNAME=${1:-}
ETCD_KEY="/networking-vpp/nodes/${HOSTNAME}/routers/ha"

# Env variables required for etcdctl
ETCD_HOST=10.1.1.1
ETCD_PORT=2379
export ETCDCTL_ENDPOINTS="http://${ETCD_HOST}:${ETCD_PORT}"
export ETCDCTL_PEERS="http://${ETCD_HOST}:${ETCD_PORT}"

# Proxy settings or bypass proxy for connecting to etcd
export no_proxy="${ETCD_HOST}"

# A key value of 1 denotes a Master VPP Router & 0 denotes a Backup Router
ETCD_VAL=0
ETCDCTL=etcdctl

# The command to write the key to etcd
COMMAND="${ETCDCTL} set ${ETCD_KEY} ${ETCD_VAL}"

${COMMAND} >& /dev/null || exit 1
exit 0
