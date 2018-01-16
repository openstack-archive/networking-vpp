#!/bin/bash
 
# The namespace to which the VPP's control plane is attached to on the host 
VPP_NAMESPACE="vpp1"
# The IP address on VPP that's being checked for Failover
VPP_IP_ADDRESS="10.1.1.254"

# The command to check if VPP is alive and well
COMMAND="ip netns exec $VPP_NAMESPACE ping -q -c3 $VPP_IP_ADDRESS"

# Return 0, if the health-check passes
if ${COMMAND} > /dev/null 2>&1;then
    exit 0
else
    exit 1
fi