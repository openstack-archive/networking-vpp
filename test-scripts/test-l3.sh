#!/usr/bin/env bash
#Author: najoy@cisco.com
#Creates a specified number of neutron networks and subnets
#Boots a VM on each of the networks (using DHCP assigned IP)
#Attaches a router (r1) interface to each of the networks
#Test:
# 1. VM rechability from the qrouter namespace
# 2. VM rechability between the two VMs 
#Reports success or failure
##TODO:Clean up

###SET PROGRAM VARIABLES####
(( num_networks=2 ))
devstack_dir=/home/demo/devstack
boot_vm=/home/demo/boot-vm
source ${devstack_dir}/openrc admin admin
network_type=flat
network_prefix=private
subnet_prefix=private
router_name=r1
#Total time to wait for the VM to be alive in the network
wait_time=120
### END PROGRAM VARIABLES####

for i in $( seq 1 $num_networks);do
  (( TOTAL_TIME=$wait_time ))
  eval network${i}=$(echo ${network_prefix}${i})
  eval subnet${i}=$(echo ${subnet_prefix}${i})
  eval cidr${i}=$(echo 10.${i}.${i}.0/24)

  net_var=$(echo network$i)
  eval network_name=\$$net_var
  subnet_var=$(echo subnet$i)
  eval subnet_name=\$$subnet_var
  cidr_var=$(echo cidr$i)
  eval cidr=\$$cidr_var
  (( VM_ALIVE=0 ))
  (( FOUND_VM=0 ))
  (( FOUND_QROUTER_NS=0 ))
  
  echo "Creating a flat network - name $network_name:  type:${network_type} physical_network:physnet"
  if ! neutron net-create --provider:physical_network=physnet${i} --provider:network_type=flat ${network_name}; then
      echo "Network: $network_name creation failed"
      exit 1
  fi 
  echo "Creating a subnet name:$subnet_name for network:$network_name with cidr:$cidr"
  if ! neutron subnet-create ${network_name} ${cidr} --name ${subnet_name}; then
      echo "Subnet: $subnet_name creation failed"
      exit 1
  fi
  echo "Adding a router interface for router:${router_name} on network:${network_name}" 
  if ! neutron router-interface-add ${router_name} ${network_name}; then
      echo "Router:$router_name interface creation failed on network:${network_name}"
      exit 1
  fi 

  echo "booting VM:vm${i} on network:${network_name}"
  ${boot_vm} vm${i} ${network_name}
  vm_ip=$(nova show vm${i} | grep network | awk '{print $5}')
  echo "VM${i}: Ip address:${vm_ip}"

  network_id=$(neutron net-list | grep ${network_name} | awk '{print $2}')
  qrouter_ns=qrouter-$(neutron router-list | grep ${router_name} | awk '{print $2}')
  echo "Checking for the presence of qrouter namespace:${qrouter_ns}"

  if sudo ip netns list | grep ${qrouter_ns}; then
     echo "Found QROUTER namespace ${qrouter_ns}"
     FOUND_QROUTER_NS=1
  fi

  if ((!FOUND_QROUTER_NS)); then
     echo "ERROR: QROUTER namespace ${qrouter_ns} could not be found"
     exit 1
  fi 

  while [[ ${TOTAL_TIME} -gt 0 ]] && ((FOUND_QROUTER_NS)) && ((!FOUND_VM)); do
     if ((VM_ALIVE)); then
        echo "Success: VM${i} is now IP rechable from the Q_ROUTER namespace!!!"
        FOUND_VM=1
     fi
     if sudo ip netns exec ${qrouter_ns} ping -c 4 ${vm_ip} > /dev/null 2>&1; then
        VM_ALIVE=1
     else
        echo "Waiting for VM${i} to be alive"
        sleep 1
        let TOTAL_TIME=${TOTAL_TIME}-5
     fi
  done 
done
