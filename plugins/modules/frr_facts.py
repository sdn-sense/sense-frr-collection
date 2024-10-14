#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gather Frr Facts"""
# Copyright: Contributors to the Ansible project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
import os
import json
import shlex
import subprocess
import sys
from ipaddress import ip_address, ip_network


def normalizedip(ipInput):
    """
    Normalize IPv6 address. It can have leading 0 or not and both are valid.
    This function will ensure same format is used.
    """
    tmp = ipInput.split("/")
    try:
        ipaddr = ip_address(tmp[0]).compressed
    except ValueError:
        ipaddr = tmp[0]
    if len(tmp) == 2:
        return f"{ipaddr}/{tmp[1]}"
    if len(tmp) == 1:
        return ipaddr
    # We return what we get here, because it had multiple / (which is not really valid)
    return ipInput


def getsubnet(ipInput, strict=False):
    """Get subnet if IP address"""
    return ip_network(ipInput, strict=strict).compressed


def ipVersion(ipInput, strict=False):
    """Check if IP is valid.
    Input: str
    Returns: (one of) IPv4, IPv6, Invalid"""
    version = -1
    try:
        version = ip_network(ipInput, strict=strict).version
    except ValueError:
        pass
    if version != -1:
        return version
    tmpIP = ipInput.split("/")
    try:
        version = ip_address(tmpIP[0]).version
    except ValueError:
        pass
    return version


def make_json_obj(inptext):
    """Make JSON object from string"""
    try:
        return json.loads(inptext)
    except json.decoder.JSONDecodeError:
        return inptext


def run_commands(module, commands, check_rc):
    """Run commands and return output)"""
    output = []
    for command in commands:
        command = shlex.split(str(command))
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if check_rc and proc.returncode != 0:
            raise Exception(f"Exception executing command {command}. Err: {err}")
        output.append(make_json_obj(out.decode("utf-8")))
    return output


class FactsBase:
    """Base class for Facts"""

    COMMANDS = []

    def __init__(self, module):
        self.module = module
        self.facts = {}
        self.responses = None

    def populate(self):
        """Populate responses"""
        self.responses = run_commands(self.module, self.COMMANDS, check_rc=False)

    def run(self, cmd):
        """Run commands"""
        return run_commands(self.module, cmd, check_rc=False)


class Config(FactsBase):
    """Default Class to get basic info"""

    COMMANDS = [
        "ip addr",
        "ip r",
        "ip -6 r"
    ]

    def populate(self):
        super(Config, self).populate()
        self.facts["config"] = self.responses


class Interfaces(FactsBase):
    """All Interfaces Class"""

    COMMANDS = []

    def _getOperStatus(self, iface):
        """Get oper status"""
        with open(f'/sys/class/net/{iface}/operstate', encoding="utf-8") as fd:
            self.facts["interfaces"][iface]["operstatus"] = fd.read().strip()

    def _getMTU(self, iface):
        """Get MTU"""
        with open(f'/sys/class/net/{iface}/mtu', encoding="utf-8") as fd:
            self.facts["interfaces"][iface]["mtu"] = int(fd.read().strip())

    def _getTxQueueLen(self, iface):
        """Get Tx Queue Length"""
        with open(f'/sys/class/net/{iface}/tx_queue_len', encoding="utf-8") as fd:
            self.facts["interfaces"][iface]["txqueuelen"] = int(fd.read().strip())

    def _getSpeed(self, iface):
        """Get Speed"""
        with open(f'/sys/class/net/{iface}/speed', encoding="utf-8") as fd:
            self.facts["interfaces"][iface]["bandwidth"] = int(fd.read().strip())

    def _getMacAddress(self, iface):
        """Get MAC Address"""
        infod = self.facts.setdefault("info", {"macs": []})
        with open(f'/sys/class/net/{iface}/address', encoding="utf-8") as fd:
            macaddr = fd.read().strip()
            self.facts["interfaces"][iface]["macaddress"] = macaddr
            if macaddr not in infod["macs"]:
                infod["macs"].append(macaddr)

    def _getIP(self, iface):
        """Get IP"""
        ifd = self.facts["interfaces"].setdefault(iface, {})
        try:
            ip_output = subprocess.check_output(f'ip -br addr show {iface}', shell=True).decode().splitlines()[0]
            ip_parts = ip_output.split()
            for part in ip_parts:
                if '/' in part:  # Check for IP address with subnet
                    if ':' in part:
                        ifd.setdefault('ipv6', [])
                        ifd['ipv6'].append({'address': part.split('/')[0],
                                            'masklen': part.split('/')[1]})
                    else:
                        ifd.setdefault('ipv4', [])
                        ifd['ipv4'].append({'address': part.split('/')[0],
                                            'masklen': part.split('/')[1]})
        except subprocess.CalledProcessError:
            pass  # No IP information

    def _getroutes(self, _iface):
        """Get Routes"""
        self.facts.setdefault("ipv4", [])
        self.facts.setdefault("ipv6", [])
        # IPv4 Routes
        for item in [['4', 'default', '0.0.0.0/0'], ['6', 'default', '::/0']]:
            ipResult = subprocess.run(['ip', f'-{item[0]}', 'route'], capture_output=True, text=True)
            ipLines = ipResult.stdout.splitlines()
            for line in ipLines:
                parts = line.split()
                if parts[0] == item[1]:
                    from_route = item[2]
                    to_route = parts[2]
                else:
                    from_route = parts[0]
                    to_route = parts[2] if 'via' in parts else parts[1]
                if to_route == 'dev' and 'src' in parts:
                    to_route = parts[parts.index('src') + 1]
                elif to_route == 'dev':
                    to_route = parts[parts.index('dev') + 1]
                nroute = {'from': from_route, 'to': to_route}
                if nroute not in self.facts[f"ipv{item[0]}"]:
                    self.facts[f"ipv{item[0]}"].append(nroute)

    def _getlldp(self, _iface):
        """Get LLDP"""
        self.facts["lldp"] = {}

    def _addSwitchPort(self, iface):
        """Add Switch Port"""
        if len(iface.split('.')) == 2:
            self.facts["interfaces"][iface]["switchport"] = 'no'
            self.facts["interfaces"][iface].setdefault("tagged", [])
            self.facts["interfaces"][iface]['tagged'].append(iface.split('.')[1])
            return
        self.facts["interfaces"][iface]["switchport"] = 'yes'
        self.facts["interfaces"][iface].setdefault("untagged", [])
        self.facts["interfaces"][iface]['untagged'].append(iface)

    def populate(self):
        super(Interfaces, self).populate()
        self.facts["interfaces"] = {}
        self._getlldp("all")
        self._getroutes("all")
        for iface in os.listdir('/sys/class/net'):
            if iface == 'lo':
                continue
            self.facts["interfaces"].setdefault(iface, {})
            self._addSwitchPort(iface)
            self._getOperStatus(iface)
            self._getMTU(iface)
            self._getTxQueueLen(iface)
            self._getSpeed(iface)
            self._getMacAddress(iface)
            self._getIP(iface)


# Get all routes
# add emptu lldp
# for all mac - add into ansible_net_inf macs dic


FACT_SUBSETS = {"interfaces": Interfaces, "config": Config}


def main():
    """main entry point for module execution"""
    facts = {"gather_subset": list(FACT_SUBSETS.keys())}
    module = "FRR"
    instances = []
    for key in facts["gather_subset"]:
        instances.append(FACT_SUBSETS[key](module))

    for inst in instances:
        if inst:
            inst.populate()
            facts.update(inst.facts)

    ansible_facts = {"ansible_facts": {}}
    for key, value in facts.items():
        key = f"ansible_net_{key}"
        ansible_facts["ansible_facts"][key] = value

    print(json.dumps(ansible_facts))
    sys.exit(0)


if __name__ == "__main__":
    main()
