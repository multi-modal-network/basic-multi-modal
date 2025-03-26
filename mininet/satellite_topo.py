# coding=utf-8
# Multi-Model topology
"""
Copyright 2019-present Open Networking Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import argparse
import os
import stratum
from stratum import StratumBmv2Switch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Host
from mininet.topo import Topo
from mininet.node import Controller, RemoteController
from mininet.link import Intf




import subprocess

CPU_PORT = 255

def ovs_service_start():
    try:
        subprocess.check_call(["service", "openvswitch-switch", "start"])
        print("Command executed successfully")
    except subprocess.CalledProcessError as e:
        print("An error occurred while trying to execute the command: {}".format(e))
    except Exception as e:
        print("An unexpected error occurred: {}".format(e))
def addOVSPort(bridge, port):
    try:
        subprocess.check_call(["ovs-vsctl", "add-port", bridge, port])
        print("Port added successfully")
    except subprocess.CalledProcessError as e:
        print("An error occurred while trying to execute the command: {}".format(e))
    except Exception as e:
        print("An unexpected error occurred: {}".format(e))
def applyOVSFlow(bridge, flow):
    try:
        subprocess.check_call(["ovs-ofctl", "add-flow", bridge] + flow.split(","))
        print("Flow applied sucessfully")
    except subprocess.CalledProcessError as e:
        print("An error occurred while trying to execute the command: {}".format(e))
    except Exception as e:
        print("An unexpected error occurred: {}".format(e))


class TutorialTopo(Topo):
    """2x2 fabric topology with IPv6 hosts"""

    def __init__(self):
        Topo.__init__(self)
        ovs_service_start()
        switch_list = []
        s1 = self.addSwitch('s1', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        switch_list.append('s1')
        ovs1 = self.addSwitch('ovs1')
        self.addLink(ovs1, s1)
        for i in range(2, 4):
            switch_name = 's{}'.format(i)
            switch = self.addSwitch(switch_name, cls=StratumBmv2Switch, cpuport=CPU_PORT)
            switch_list.append(switch_name)



switches = {'stratum-bmv2': StratumBmv2Switch}

TOPOS = {'tutorialtopo':TutorialTopo}

topos = {'custom': (lambda: TutorialTopo())}


def main():
    #modify_port('/home/eis/P4/onos/tools/dev/mininet/stratum.py', 'nextGrpcPort', 60000)
    #reload(stratum)
    ovs_service_start()
    net = Mininet(topo=TutorialTopo(), controller=None)
    #c0 = net.addController(name='c0', controller=RemoteController, ip='192.168.2.139', port=6653)
    net.start()

    # 添加ovs


    CLI(net)
    net.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Mininet topology script for 2x2 fabric with stratum_bmv2 and IPv6 hosts')
    args = parser.parse_args()
    setLogLevel('info')

    main()


