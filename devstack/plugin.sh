# plugin - DevStack plugin.sh dispatch script for vpp

vpp_debug() {
    if [ ! -z "$VPP_DEVSTACK_DEBUG" ] ; then
       "$@" || true # a debug command failing is not a failure
    fi
}

# For debugging purposes, highlight vpp sections
vpp_debug tput setab 1

name=networking-vpp

#GITREPO[$name]=${VPP_REPO:-https://github.com/iawells/networking-vpp.git}
#GITBRANCH[$name]=${VPP_BRANCH:-master}
#GITDIR[$name]="$MECH_VPP_DIR"

# All machines using the VPP mechdriver and agent
function pre_install_vpp {
    :
}

function install_vpp {
    cd "$MECH_VPP_DIR"
    echo "Installing networking-vpp"
    setup_develop "$MECH_VPP_DIR"
}

function init_vpp {
    :
}

function configure_vpp {
    iniset /$Q_PLUGIN_CONF_FILE ml2_vpp agents $MECH_VPP_AGENTLIST

    if [ ! -z "$VLAN_TRUNK_IF" ] ; then
       iniset /$Q_PLUGIN_CONF_FILE ml2_vpp vlan_trunk_if $VLAN_TRUNK_IF
    fi

    if [ ! -z "$VXLAN_SRC_ADDR" ] ; then
       iniset /$Q_PLUGIN_CONF_FILE ml2_vpp vxlan_src_addr $VXLAN_SRC_ADDR
    fi

    if [ ! -z "$VXLAN_BCAST_ADDR" ] ; then
       iniset /$Q_PLUGIN_CONF_FILE ml2_vpp vxlan_bcast_addr $VXLAN_BCAST_ADDR
    fi

    if [ ! -z "$VXLAN_VRF" ] ; then
       iniset /$Q_PLUGIN_CONF_FILE ml2_vpp vxlan_vrf $VXLAN_VRF
    fi

}

function shut_vpp_down {
    :
}


# The VPP control plane element (we don't at this point start VPP itself TODO)

agent_service_name=vpp-agent

function pre_install_vpp_agent {
    :
}

function install_vpp_agent {
    :
}

function init_vpp_agent {
    # sudo for now, as it needs to connect to VPP and for that requires root privs
    # to share its shmem comms channel
    run_process $agent_service_name "sudo $VPP_CP_BINARY --config-file /$Q_PLUGIN_CONF_FILE"
}

function configure_vpp_agent {
    :
}

function shut_vpp_agent_down {
    stop_process $agent_service_name
}



agent_do() {
    if is_service_enabled "$agent_service_name"; then
       "$@"
    fi
}

if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
    # Set up system services
    echo_summary "Configuring system services $name"
    pre_install_vpp
    agent_do pre_install_vpp_agent

elif [[ "$1" == "stack" && "$2" == "install" ]]; then
    # Perform installation of service source
    echo_summary "Installing $name"
    install_vpp
    agent_do install_vpp_agent

elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    # Configure after the other layer 1 and 2 services have been configured
    echo_summary "Configuring $name"
    configure_vpp
    agent_do configure_vpp_agent

elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
# Initialize and start the service
    echo_summary "Initializing $name"
    init_vpp
    agent_do init_vpp_agent
fi

if [[ "$1" == "unstack" ]]; then
    # Shut down services
    shut_vpp_down
    agent_do shut_vpp_agent_down
fi

if [[ "$1" == "clean" ]]; then
    # Remove state and transient data
    # Remember clean.sh first calls unstack.sh
    # no-op
    :
fi
vpp_debug tput setab 9

function neutron_plugin_install_agent_packages {
    install_package bridge-utils
}

# We have opinions on the interface driver that should attach agents
function neutron_plugin_setup_interface_driver {
    local conf_file=$1
    iniset $conf_file DEFAULT interface_driver linuxbridge
}
