import os
import sys
import subprocess

try:
    import click
except ImportError:
    print("Please install click (pip3 install click")
    sys.exit(2)

ETCDCTL_PATH = "etcdctl"
PASSWORD_PREFIX = "_CHANGE_ME_NOW_!"
ENDPOINT = None

####################### Generic Helper methods #########################################################################

def _which(program):

    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None

######################## Helper OpenStack functions ####################################################################


def _list_compute_nodes():
    #TODO: use REST API of Python API instead
    #nova_manage_output = subprocess.check_output("nova-manage host list | grep nova-compute | tr -s ' '| cut  -d ' ' -f2", shell=True)
    output = subprocess.check_output("openstack host list | grep compute | cut -d '|' -f 2 | tr -d ' '", shell=True)
    str_output = output.decode()
    return str_output.split('\n')[:-1]


def _list_network_controllers():
    #TODO: use REST API of Python API instead
    #subprocess.check_output("nova-manage service list | grep nova-compute | tr -s ' '| cut  -d ' ' -f2", shell=True)
    output = subprocess.check_output("openstack  endpoint list | grep neutron | cut -d'|' -f 8 | cut -d':' -f2 | tr -d '/' ", shell=True)
    str_output = output.decode()
    return str_output.split('\n')[:-1]


####################### Wrapped etcdctl commands #######################################################################

def exec_etcdctl(*command, **argv):
    try:
        return subprocess.check_output([ETCDCTL_PATH, "--endpoint", ENDPOINT] + list(command), **argv)
    except subprocess.CalledProcessError as e:
        print("[-] Error executing command: {}".format(e))



@click.group()
@click.option('--endpoint', default="127.0.0.1:2379", help='Endpoint of the management interface of etcd (host:port)')
def etcdctl(endpoint):
    print("[*] connecting to endpoing {}".format(endpoint))
    global ENDPOINT
    ENDPOINT = endpoint


def list_roles():
    print("[+] Roles:")
    exec_etcdctl("role", "list")


def create_user(username, password=None):
    if password is not None:
        print("[+] Creating user {user}:".format(user=username))
    else:
        print("[+] Creating user {user} with password {password}".format(user=username, password=password))
    exec_etcdctl("user", "add", username, input=password.encode())


def remove_user(username):
    print("[+] removing user {user}".format(user=username))
    exec_etcdctl("user", "remove", username)


def create_role(role):
    print("[+] creating role {role}".format(role=role))
    exec_etcdctl("role", "add", role)


def set_user_role(username, role):
    print("[+] Granting {role} to user {user}".format(role=role, user=username))
    exec_etcdctl("user", "grant", username, "-roles", role)


def set_role_permission(role, path, perm):
    if perm not in ['read', 'write', 'readwrite']:
        raise ValueError
    print("[+] Granting {perm} on {path} to role {role}".format(role=role, path=path, perm=perm))
    exec_etcdctl("role", "grant", role, "-path", path, "-"+perm)


@etcdctl.command()
def enable_authentication():
    exec_etcdctl("auth", "enable")


################################### Magick / Smart configuration #######################################################
@etcdctl.command(help="automated configuration of etcd")
def smart_config():
    #list existing compute nodes
    compute_nodes = _list_compute_nodes()
    network_controllers = _list_network_controllers()

    for c in compute_nodes:
        print("[+]\tFound Compute {}".format(c))

    for c in network_controllers:
        print("[+]\tFound Network {}".format(c))

    #create a role and user per compute node and per network node
    for compute_node in compute_nodes:
        rolename = "ROLE_COMPUTE_{}".format(compute_node)
        username = "USER_COMPUTE_{}".format(compute_node)
        password = compute_node+PASSWORD_PREFIX
        create_role(rolename)
        create_user(username, password)
        set_user_role(username, rolename)
        click.echo("[+] creating user '{}', role '{}', password '{}'".format(username, rolename, password))
        click.echo("[!] Please change password !")
        ## PERMISSIONS ##
        set_role_permission(rolename, "/networking-vpp/nodes/{}/*".format(compute_node), "read")
        set_role_permission(rolename, "/networking-vpp/state/{}/*".format(compute_node), "readwrite")

    for network_controller in network_controllers:
        rolename = "ROLE_NETWORK_{}".format(network_controller)
        username = "USER_NETWORK_{}".format(network_controller)
        password = network_controller+PASSWORD_PREFIX
        create_role(rolename)
        create_user(username, password)
        click.echo("[+] creating user '{}', role '{}', password '{}'".format(username, rolename, password))
        click.echo("[!] Please change password !")
        set_user_role(username, rolename)
        ## PERMISSION ##
        set_role_permission(rolename, "/networking-vpp/nodes/*", "readwrite")
        set_role_permission(rolename, "/networking-vpp/state/*", "read")

    if click.confirm('Enable ETCD authentication ?'):
        print("[*] Enabling ETCD authentication")
        enable_authentication()



################################ Main (please go away !) ###############################################################
def run_checks():
    if sys.version_info[0] < 3:
        print("Script support Python 3.x only !")
        sys.exit(1)

    global ETCDCTL_PATH
    ETCDCTL_PATH = _which(ETCDCTL_PATH)
    if ETCDCTL_PATH is None:
        print("etcdctl not found PATH")
        sys.exit(3)


if __name__ == '__main__':
    run_checks()
    etcdctl()