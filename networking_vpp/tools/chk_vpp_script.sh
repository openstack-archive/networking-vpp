#!/bin/bash

# This script is run by keepalived to check the health of VPP.
# It returns 0 if the health-check passes and 1 otherwise.
# Set the correct IP address of VPP in the variable VPP_IP_ADDRESS.

# The namespace to which the VPP's control plane is attached to on the host.
VPP_NAMESPACE="vpp1"
# The IP address on VPP checked for liveness.
VPP_IP_ADDRESS="10.1.1.254"

# The command to check if the VPP is alive and well
COMMAND="ip netns exec $VPP_NAMESPACE ping -q -c3 $VPP_IP_ADDRESS"

# Return 1, if the health-check fails
${COMMAND} >& /dev/null || exit 1
exit 0
