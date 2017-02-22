#!/usr/bin/python
# Copyright (c) 2016 Cisco Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import click
import jsonutils
import os
import subprocess
import sys

from networking_vpp._i18n import _


ETCDCTL_PATH = "etcdctl"
ENDPOINT = None
CAFILE = None


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


def check_output_input(*args, **kwargs):

    if sys.version_info[0] >= 3:
        return subprocess.check_output(*args, **kwargs)
    else:
        if 'stdout' in kwargs:
            raise ValueError(_('stdout argument not allowed, '
                               'it will be overridden.'))
        if 'input' in kwargs:
            if 'stdin' in kwargs:
                raise ValueError(_('stdin and input arguments '
                                   'may not both be used.'))
            inputdata = kwargs['input']
            del kwargs['input']
            kwargs['stdin'] = subprocess.PIPE
        else:
            inputdata = None

        process = subprocess.Popen(*args, stdout=subprocess.PIPE, **kwargs)

        try:
            output, unused_err = process.communicate(inputdata)
        except Exception as e:
            process.kill()
            process.wait()
            raise e

        retcode = process.poll()

        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = args[0]
            raise subprocess.CalledProcessError(retcode, cmd, output=output)
        return output


def exec_etcdctl(*command, **argv):
    # This function is required because the python-etcd library does not
    # support RBAC actions.
    try:
        if CAFILE is None:
            return check_output_input(
                [ETCDCTL_PATH, "--endpoint", ENDPOINT] + list(command),
                **argv)
        else:
            return check_output_input(
                [ETCDCTL_PATH,
                 "--endpoint", ENDPOINT, "--ca-file", CAFILE] + list(command),
                **argv)
    except subprocess.CalledProcessError as e:
        print("[-] Error executing command: {}".format(e))


@click.group()
@click.option('--endpoint', default="127.0.0.1:2379",
              help='Endpoint of the management interface of etcd (host:port)')
@click.option('--ca', default=None, help='CA file path if TLS is enabled')
def etcdctl(endpoint, ca):
    print("[*] connecting to endpoint {} ...".format(endpoint))
    global ENDPOINT
    ENDPOINT = endpoint
    if endpoint.startswith("https://"):
        global CAFILE
        CAFILE = ca


def list_roles():
    print("[+] Roles:")
    exec_etcdctl("role", "list")


def create_user(username, password):
    print("[+] Creating user {user}:".format(user=username))
    exec_etcdctl("user", "add", username, input=password)


def remove_user(username):
    print("[+] removing user {user}".format(user=username))
    exec_etcdctl("user", "remove", username)


def create_role(role):
    print("[+] creating role {role}".format(role=role))
    exec_etcdctl("role", "add", role)


def set_user_role(username, role):
    print("[+] Granting {role} to user {user}".format(
        role=role, user=username))
    exec_etcdctl("user", "grant", username, "-roles", role)


def set_role_permission(role, path, perm):
    if perm not in ['read', 'write', 'readwrite']:
        raise ValueError
    print("[+] Granting {perm} on {path} to role {role}".format(
        role=role, path=path, perm=perm))
    exec_etcdctl("role", "grant", role, "-path", path, "-" + perm)


@etcdctl.command()
def enable_authentication():
    exec_etcdctl("auth", "enable")


@etcdctl.command(help="automated configuration of etcd")
@click.argument('conf', click.Path(exists=True))
def smart_config(conf):
    # list existing compute nodes
    json_conf = jsonutils.load(open(conf))

    compute_nodes = json_conf['compute']
    network_controllers = json_conf['network']

    for c in compute_nodes:
        print("[+]\tFound Compute {}".format(c))

    for c in network_controllers:
        print("[+]\tFound Network {}".format(c))

    # create a role and user per compute node and per network node
    for compute_node, param in compute_nodes.items():
        rolename = param['role']
        username = param['username']
        password = param['password']
        create_role(rolename)
        create_user(username, password)
        set_user_role(username, rolename)
        print("[+] creating user '{}', role '{}'".format(
            username, rolename))
        # PERMISSIONS
        set_role_permission(
            rolename,
            "/networking-vpp/nodes/{}/*".format(compute_node), "read")
        set_role_permission(
            rolename,
            "/networking-vpp/state/{}/*".format(compute_node), "readwrite")

    for network_controller, param in network_controllers.items():
        rolename = param['role']
        username = param['username']
        password = param['password']
        create_role(rolename)
        create_user(username, password)
        print("[+] creating user '{}', role '{}'".format(
            username, rolename))

        set_user_role(username, rolename)
        # PERMISSION
        set_role_permission(
            rolename,
            "/networking-vpp/nodes/*", "readwrite")
        set_role_permission(
            rolename,
            "/networking-vpp/state/*", "read")

    if click.confirm('Enable ETCD authentication ?'):
        print("[*] Enabling ETCD authentication")
        enable_authentication()


def run_checks():
    global ETCDCTL_PATH
    ETCDCTL_PATH = _which(ETCDCTL_PATH)
    if ETCDCTL_PATH is None:
        print("etcdctl not found PATH")
        sys.exit(3)


if __name__ == '__main__':
    run_checks()
    etcdctl()
