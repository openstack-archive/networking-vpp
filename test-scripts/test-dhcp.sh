#!/usr/bin/env bash
#Author: najoy@cisco.com
#Creates a specified number of neutron networks and subnets
#Boots a VM on each of the networks (using DHCP assigned IP)
#Tests VM rechability from the DHCP namespace
#Reports success or failure
##TODO:Clean up

###SET PROGRAM VARIABLES####
(( num_networks=2 ))
devstack_dir=/home/demo/devstack
boot_vm=./boot-vm
source ${devstack_dir}/openrc admin admin
network_type=flat
network_prefix=private
subnet_prefix=private
#Total time to wait for the VM to be alive in the network
wait_time=120
### END PROGRAM VARIABLES####

for i in $( seq 1 $num_networks);do
  (( TOTAL_TIME=$wait_time ))
  eval network${i}=$(echo ${network_prefix}${i})
  eval subnet${i}=$(echo ${subnet_prefix}${i})
  eval cidr${i}=$(echo 10.${i}.${i}.0/24)

  net_var=$(echo network$i)
  #Assign the value of the variable "net_var" to the network_name variable..and so on
  eval network_name=\$$net_var
  subnet_var=$(echo subnet$i)
  eval subnet_name=\$$subnet_var
  cidr_var=$(echo cidr$i)
  eval cidr=\$$cidr_var
  (( VM_ALIVE=0 ))
  (( FOUND_VM=0 ))
  (( FOUND_DHCP_NS=0 ))
  
  echo "Creating a flat network - name $network_name:  type:${network_type} physical_network:physnet"
  if ! neutron net-create --provider:physical_network=physnet${i} --provider:network_type=flat ${network_name}; then
      echo "Network: $network_name creation failed"
      exit 1
  fi 
  echo "Creating a subnet name:$subnet_anem for network:$network_name with cidr:$cidr"
  if ! neutron subnet-create ${network_name} ${cidr} --name ${subnet_name}; then
      echo "Subnet: $subnet_name creation failed"
      exit 1
  fi 

  echo "booting VM: vm${i} on network:${network_name}"
  ${boot_vm} vm${i} ${network_name}
  vm_ip=$(nova show vm${i} | grep network | awk '{print $5}')
  echo "VM${i}: Ip address:${vm_ip}"

  network_id=$(neutron net-list | grep ${network_name} | awk '{print $2}')
  qdhcp_ns=qdhcp-${network_id}
  echo "Checking for the presence of qdhcp namespace: ${qdhcp_ns}"

  if sudo ip netns list | grep ${qdhcp_ns}; then
     echo "Found DHCP namespace ${qdhcp_ns}"
     FOUND_DHCP_NS=1
  fi

  if ((!FOUND_DHCP_NS)); then
     echo "ERROR: DHCP namespace ${qdhcp_ns} could not be found"
     exit 1
  fi 

  while [[ ${TOTAL_TIME} -gt 0 ]] && ((FOUND_DHCP_NS)) && ((!FOUND_VM)); do
     if ((VM_ALIVE)); then
        echo "Success!!: VM${i} is now IP reachable from the DHCP namespace!!!"
        FOUND_VM=1
     fi
     if sudo ip netns exec ${qdhcp_ns} ping -c 4 ${vm_ip} > /dev/null 2>&1; then
        VM_ALIVE=1
     else
        echo "Waiting for VM${i} to be alive"
        sleep 1
        let TOTAL_TIME=${TOTAL_TIME}-5
     fi
  done 
done
