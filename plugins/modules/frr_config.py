#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
SENSE Frr Module, which is copied and called via Ansible from
SENSE Site-RM Resource Manager.
"""
import time
import ast
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
from ipaddress import ip_network
import datetime
import uuid

# TODO: Make it configurable
vtyshcmd = "docker exec -i frr vtysh"
vppshcmd = "docker exec -i vpp vppctl"
defmtu = 9000
deftxqueuelen = 10000

RUNUUID = str(uuid.uuid4())
DATE_STR = datetime.datetime.now().strftime('%Y-%m-%d')

class CustomLogger:
    """Custom Logger class"""
    def __init__(self, logDir="/tmp", logPrefix="ansible-sense-frr-config", logService="MAIN"):
        self.logFileMain = os.path.join(logDir, f"{logPrefix}-{DATE_STR}.stdout.log")
        self.logFileUUID = os.path.join(logDir, f"{logPrefix}-{DATE_STR}-{RUNUUID}.stdout.log")
        self.logService = logService

    def _getTimestamp(self):
        """Get timestamp"""
        return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def _createLogFile(self, fname):
        """Create log file"""
        try:
            with open(fname, "a", encoding="utf-8") as log:
                log.write(f"[{self.logService}]Log file created at {self._getTimestamp()}\n")
        except OSError:
            return False
        return True

    def __writeLogUUID(self, message, level):
        """Write log message"""
        if not self._createLogFile(self.logFileUUID):
            return
        timestamp = self._getTimestamp()
        logEntry = f"{timestamp} - {level} - {self.logService} - {message}"
        with open(self.logFileUUID, "a", encoding="utf-8") as log:
            log.write(logEntry + "\n")

    def _writeLog(self, message, level):
        """Write log message"""
        if not self._createLogFile(self.logFileMain):
            return
        timestamp = self._getTimestamp()
        logEntry = f"{timestamp} - {level} - {self.logService} - {message}"
        with open(self.logFileMain, "a", encoding="utf-8") as log:
            log.write(logEntry + "\n")
        self.__writeLogUUID(message, level)

    def info(self, message):
        """Log info message"""
        self._writeLog(message, "INFO")

    def warning(self, message):
        """Log warning message"""
        self._writeLog(message, "WARNING")

    def error(self, message):
        """Log error message"""
        self._writeLog(message, "ERROR")

    def getRunContent(self):
        """Get log content"""
        logcontent = []
        if os.path.isfile(self.logFileUUID):
            with open(self.logFileUUID, "r", encoding="utf-8") as log:
                logcontent = log.readlines()
        return logcontent

    def deleteRunContent(self):
        """Delete log content"""
        if os.path.isfile(self.logFileUUID):
            os.remove(self.logFileUUID)


def getBroadCast(inIP):
    """Return broadcast IP."""
    myNet = ip_network(str(inIP), strict=False)
    return str(myNet.broadcast_address)

def normalizeIPAddress(ipInput):
    """Normalize IP Address"""
    tmpIP = ipInput.split("/")
    longIP = ipaddress.ip_address(tmpIP[0]).exploded
    if len(tmpIP) == 2:
        return f"{longIP}/{tmpIP[1]}"
    return longIP


def externalCommand(command):
    """Execute External Commands and return stdout and stderr."""
    logger = CustomLogger(logService="ExternalCommand")
    logger.info(f"Executing command: {command}")
    command = shlex.split(command)
    stdout, stderr, exitCode = "", "", -1
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        stdout, stderr = proc.communicate()
        exitCode = proc.wait()
        if exitCode != 0:
            stderr = [f"Error: {command} exited non-zero. Exit: {exitCode}"] + stderr.decode("utf-8").split("\n")
    logger.info(f"Command: {command} executed. Exit: {exitCode} Stdout: {stdout} Stderr: {stderr}")
    return [stdout, stderr, exitCode]


def sendviaStdIn(maincmd, commands):
    """Send commands to maincmd stdin"""
    logger = CustomLogger(logService="sendviaStdIn")
    if not isinstance(maincmd, list):
        maincmd = shlex.split(maincmd)
    with subprocess.Popen(maincmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as mainProc:
        singlecmd = ""
        for cmd in commands:
            singlecmd += f"{cmd}\n"
        logger.info(f"Sending commands: {singlecmd}")
        stdout, stderr = mainProc.communicate(input=singlecmd.encode())
        exitCode = mainProc.wait()
        logger.info(f"Commands: {singlecmd} executed. Exit: {exitCode} Stdout: {stdout} Stderr: {stderr}")


def strtojson(intxt):
    """str to json function"""
    out = {}
    try:
        out = ast.literal_eval(intxt)
    except ValueError:
        out = json.loads(intxt)
    except SyntaxError as ex:
        raise Exception(f"SyntaxError: Failed to literal eval dict. Err:{ex} ") from ex
    return out


def loadJson(infile):
    """Load json file and return dictionary"""
    out = {}
    fout = ""
    if not os.path.isfile(infile):
        raise Exception(f"File does not exist {infile}. Exiting")
    with open(infile, "r", encoding="utf-8") as fd:
        fout = fd.readlines()
    if fout:
        for line in fout:
            splline = line.split(": ", 1)
            if len(splline) == 2:
                out[splline[0]] = strtojson(splline[1])
    return out

class VppCmd:
    """VPP CMD Executor API"""
    def __init__(self):
        self.active = False
        self.__checkVpp()
        self.logger = CustomLogger(logService="VPP")

    def __getInterface(self, intf):
        """Get Interface. SENSE uses e1, e2, while vpp config expects Ethernet2/0/0"""
        index = intf[1:]
        return f"Ethernet{index}/0/0"

    def __checkVpp(self):
        """Check if VPP is active"""
        self.active = True
        out = externalCommand(f"sudo {vppshcmd} show int")
        if out[2] != 0:
            self.active = False

    def addVlan(self, **kwargs):
        """Add Vlan if not present"""
        out = externalCommand(f"sudo {vppshcmd} create sub-interfaces {self.__getInterface(kwargs['interface'])} {kwargs['vlanid']}")
        if out[2] != 0:
            self.logger.error(f"Failed to add Vlan {kwargs['vlanid']} to {kwargs['interface']}")
            raise Exception(f"Failed to add Vlan {kwargs['vlanid']} to {kwargs['interface']}")
        self._confVlan(**kwargs)

    def _confVlan(self, **kwargs):
        """Configure Vlan"""
        out = externalCommand(f"sudo {vppshcmd} set interface state {self.__getInterface(kwargs['interface'])}.{kwargs['vlanid']} up")
        if out[2] != 0:
            self.logger.error(f"Failed to set Vlan {kwargs['vlanid']} to up")
            raise Exception(f"Failed to set Vlan {kwargs['vlanid']} to up")

    def addIP(self, **kwargs):
        """Add IP if not present"""
        out = externalCommand(f"sudo {vppshcmd} set interface ip address {self.__getInterface(kwargs['interface'])}.{kwargs['vlanid']} {kwargs['ip']}")
        if out[2] != 0:
            self.logger.error(f"Failed to add IP {kwargs['ip']} to {kwargs['interface']}.{kwargs['vlanid']}")
            raise Exception(f"Failed to add IP {kwargs['ip']} to {kwargs['interface']}.{kwargs['vlanid']}")

    def delVlan(self, **kwargs):
        """Delete Vlan if present"""
        out = externalCommand(f"sudo {vppshcmd} delete sub-interface {self.__getInterface(kwargs['interface'])}.{kwargs['vlanid']}")
        if out[2] != 0:
            self.logger.error(f"Failed to delete Vlan {kwargs['vlanid']} to {kwargs['interface']}")
            raise Exception(f"Failed to delete Vlan {kwargs['vlanid']} to {kwargs['interface']}")

    def delIP(self, **kwargs):
        """Delete IP if present"""
        out = externalCommand(f"sudo {vppshcmd} set interface ip address del {self.__getInterface(kwargs['interface'])}.{kwargs['vlanid']} {kwargs['ip']}")
        if out[2] != 0:
            self.logger.error(f"Failed to delete IP {kwargs['ip']} to {kwargs['interface']}.{kwargs['vlanid']}")
            raise Exception(f"Failed to delete IP {kwargs['ip']} to {kwargs['interface']}.{kwargs['vlanid']}")


class IPCmd:
    """IP CMD Executor API"""
    def __init__(self):
        self.active = False
        self.config = {}
        self.needRefresh = True
        self.checkIP()
        self.logger = CustomLogger(logService="IPCmd")

    def checkIP(self):
        """Check if IP is active"""
        self.active = True
        out = externalCommand("ip -o addr show")
        if out[2] != 0:
            self.active = False

    def generateFrrDict(self):
        """Generate all Vlan Info for comparison with SENSE FE Entries"""
        for ipr in [4, 6]:
            result = subprocess.run(['ip', '-o', f'-{ipr}', 'addr', 'show'], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                iface = line.split()[1]
                ifacespl = iface.split('.')
                if len(ifacespl) == 2:
                    inD = self.config.setdefault(f'Vlan{ifacespl[1]}', {})
                    inT = inD.setdefault('tagged_members', [])
                    if iface not in inT:
                        inT.append(iface)
                    inIP = inD.setdefault('ips', [])
                    ip_with_mask =normalizeIPAddress(line.split()[3])
                    if ip_with_mask not in inIP:
                        inIP.append(ip_with_mask)

    def __executeCommand(self, cmd, retries=3):
        """Execute command and set needRefresh to True"""
        while retries:
            try:
                externalCommand(cmd)
                self.needRefresh = True
                return
            except Exception as ex:
                self.logger.warning(f"Failed to execute command {cmd}. Retries left: {retries}. Exception: {ex}")
                retries -= 1
                if not retries:
                    self.logger.error(f"Failed to execute command {cmd}. Exception: {ex}")
                    raise ex
                time.sleep(1)

    def __refreshConfig(self):
        """Refresh config from Switch"""
        if self.needRefresh:
            self.config = {}
            self.generateFrrDict()
            self.needRefresh = False

    def addVlan(self, **kwargs):
        """Add Vlan if not present"""
        self.__refreshConfig()
        if kwargs["vlan"] not in self.config:
            cmd = f"sudo ip link add link {kwargs['interface']} name {kwargs['interface']}.{kwargs['vlanid']} type vlan id {kwargs['vlanid']}"
            self.__executeCommand(cmd)
            self._confVlan(**kwargs)

    def _confVlan(self, **kwargs):
        """Configure Vlan with MTU and TXQUEUELEN"""
        self.__refreshConfig()
        for cmd in [f"sudo ip link set dev {kwargs['interface']}.{kwargs['vlanid']} up",
                    f"sudo ip link set dev {kwargs['interface']}.{kwargs['vlanid']} mtu {defmtu}",
                    f"sudo ip link set dev {kwargs['interface']}.{kwargs['vlanid']} txqueuelen {deftxqueuelen}"]:
            self.__executeCommand(cmd)

    def addIP(self, **kwargs):
        """Add IP if not present"""
        self.addVlan(**kwargs)
        self.__refreshConfig()
        if kwargs["ip"] not in self.config.get(kwargs["vlanid"], {}).get("ips", []):
            cmd = f"sudo ip addr add {kwargs['ip']} broadcast {getBroadCast(kwargs['ip'])} dev {kwargs['interface']}.{kwargs['vlanid']}"
            self.__executeCommand(cmd)

    def delVlan(self, **kwargs):
        """Del Vlan if present. Del All Members, IPs too (required)"""
        # First we need to clean all IPs and tagged members from VLAN
        self.delIP(**kwargs)
        self.__refreshConfig()
        if kwargs["vlan"] in self.config:
            for cmd in [f"sudo ip link set dev {kwargs['interface']}.{kwargs['vlanid']} down",
                        f"sudo ip link delete dev {kwargs['interface']}.{kwargs['vlanid']}"]:
                self.__executeCommand(cmd)

    def delIP(self, **kwargs):
        """Del IP if not present"""
        self.__refreshConfig()
        if "ip" in kwargs:
            cmd = f"sudo ip addr del {kwargs['ip']} broadcast {getBroadCast(kwargs['ip'])} dev {kwargs['interface']}.{kwargs['vlanid']}"
            try:
                self.__executeCommand(cmd)
            except Exception as ex:
                self.logger.warning(f"Failed to delete IP {kwargs['ip']} from {kwargs['interface']}.{kwargs['vlanid']}. Exception: {ex}")
                # This can fail if whole interface is deleted and not IP is changed.
                # In case of IP change - this will not except.
        else:
            for delip in self.config.get(kwargs["vlan"], {}).get("ips", []):
                kwargs["ip"] = delip
                self.delIP(**kwargs)


class FrrCmd:
    """Frr CMD Executor API"""

    def __init__(self):
        self.logger = CustomLogger(logService="FrrCmd")
        self.controller = VppCmd()
        if not self.controller.active:
            self.logger.error("VPP is not active. Will use IPCmd")
            self.controller = IPCmd()

    def addVlan(self, **kwargs):
        """Add Vlan if not present"""
        self.controller.addVlan(**kwargs)

    def addIP(self, **kwargs):
        """Add IP if not present"""
        self.controller.addIP(**kwargs)

    def delVlan(self, **kwargs):
        """Del Vlan if present. Del All Members, IPs too (required)"""
        self.controller.delVlan(**kwargs)


    def delIP(self, **kwargs):
        """Del IP if not present"""
        self.controller.delIP(**kwargs)

class vtyshParser:
    """Vtysh running config parser"""

    def __init__(self):
        self.running_config = {}
        self.stdout = ""
        self.totalLines = 0
        self.regexes = {
            "network": r"network ([0-9a-f.:]*)/([0-9]{1,3})",
            "neighbor-route-map": r"neighbor ([a-zA-z_:.0-9-]*) route-map ([a-zA-z_:.0-9-]*) (in|out)",
            "neighbor-remote-as": r"neighbor ([0-9a-f.:]*) remote-as ([0-9]*)",
            "neighbor-act": r"neighbor ([a-zA-z_:.0-9-]*) activate",
            "address-family": r"address-family (ipv[46]) ([a-z]*)",
            "ipv4-prefix-list": r"ip prefix-list ([a-zA-Z0-9_-]*) seq ([0-9]*) permit ([0-9a-f.:]*/[0-9]{1,2})",
            "ipv6-prefix-list": r"ipv6 prefix-list ([a-zA-Z0-9_-]*) seq ([0-9]*) permit ([0-9a-f.:]*/[0-9]{1,3})",
            "route-map": r"route-map ([a-zA-Z0-9_-]*) permit ([0-9]*)",
            "match-ipv4": r"match ip address prefix-list ([a-zA-Z0-9_-]*)",
            "match-ipv6": r"match ipv6 address prefix-list ([a-zA-Z0-9_-]*)",
            "router": r"^router bgp ([0-9]*)",
        }

    def _parseAddressFamily(self, incr, iptype="unset"):
        """Parse address family from running config"""
        addrFam = (
            self.running_config.setdefault("bgp", {})
            .setdefault("address-family", {})
            .setdefault(iptype, {})
        )
        networks = addrFam.setdefault("network", {})
        routeMap = addrFam.setdefault("route-map", {})
        for i in range(incr, self.totalLines):
            incr = i
            if self.stdout[incr].strip() == "exit-address-family":
                return incr
            match = re.search(self.regexes["network"], self.stdout[incr].strip(), re.M)
            if match:
                normIP = normalizeIPAddress(match[1])
                networks[normIP] = {"ip": normIP, "range": match[2]}
                continue
            match = re.search(
                self.regexes["neighbor-route-map"], self.stdout[incr].strip(), re.M
            )
            if match:
                routeMap.setdefault(match[1], {}).setdefault(match[2], match[3])
                continue
            match = re.search(
                self.regexes["neighbor-act"], self.stdout[incr].strip(), re.M
            )
            if match:
                routeMap.setdefault(match[1], {}).setdefault("activate", True)
        return incr

    def parseRouterInfo(self, incr):
        """Parse Router info from running config"""
        bgp = self.running_config.setdefault("bgp", {})
        match = re.search(self.regexes["router"], self.stdout[incr], re.M)
        if match:
            bgp["asn"] = match.group(1)
        for i in range(incr, self.totalLines):
            incr = i
            if self.stdout[i] == "!":
                return i
            match = re.search(
                self.regexes["neighbor-remote-as"], self.stdout[i].strip(), re.M
            )
            if match:
                neighbor = bgp.setdefault("neighbor", {})
                normIP = normalizeIPAddress(match[1])
                neighbor[normIP] = {"ip": normIP, "remote-as": match[2]}
                continue
            match = re.search(
                self.regexes["address-family"], self.stdout[i].strip(), re.M
            )
            if match:
                bgp.setdefault("address-family", {}).setdefault(
                    match[1], {"type": match[2]}
                )
                i = self._parseAddressFamily(i, match[1])
        return incr

    def parserPrefixList(self, incr):
        """Parse Prefix List from running config"""
        prefList = self.running_config.setdefault(
            "prefix-list", {"ipv4": {}, "ipv6": {}}
        )
        match = re.search(
            self.regexes["ipv4-prefix-list"], self.stdout[incr].strip(), re.M
        )
        if match:
            prefList["ipv4"].setdefault(match[1], {})[
                normalizeIPAddress(match[3])
            ] = match[2]
            return incr
        match = re.search(
            self.regexes["ipv6-prefix-list"], self.stdout[incr].strip(), re.M
        )
        if match:
            prefList["ipv6"].setdefault(match[1], {})[
                normalizeIPAddress(match[3])
            ] = match[2]
        return incr

    def parserRouteMap(self, incr):
        """Parse Route map info from running config"""
        routeMap = self.running_config.setdefault("route-map", {})
        match = re.search(self.regexes["route-map"], self.stdout[incr].strip(), re.M)
        if not match:
            return incr
        rMap = routeMap.setdefault(match[1], {}).setdefault(match[2], {})
        for i in range(incr, self.totalLines):
            incr = i
            if self.stdout[i] == "!":
                return i
            match = re.search(self.regexes["match-ipv4"], self.stdout[i].strip(), re.M)
            if match:
                rMap[match[1]] = ""
            match = re.search(self.regexes["match-ipv6"], self.stdout[i].strip(), re.M)
            if match:
                rMap[match[1]] = ""
        return incr

    def getConfig(self):
        """Get vtysh running config and parse it to dict format"""
        vtyshProc = externalCommand(f"{vtyshcmd} -c 'show running-config'")
        self.stdout = vtyshProc[0].decode("utf-8").split("\n")
        self.totalLines = len(self.stdout)
        for i in range(self.totalLines):
            if self.stdout[i].startswith("router bgp"):
                i = self.parseRouterInfo(i)
            elif self.stdout[i].startswith("ip prefix-list") or self.stdout[
                i
            ].startswith("ipv6 prefix-list"):
                i = self.parserPrefixList(i)
            elif self.stdout[i].startswith("route-map"):
                i = self.parserRouteMap(i)


class vtyshConfigure:
    """vtysh configure"""

    def __init__(self):
        self.commands = []
        self.logger = CustomLogger(logService="vtyshConfigure")

    def _genPrefixList(self, parser, newConf):
        """Generate Prefix lists"""

        def genCmd(pItem, noCmd=False):
            if noCmd:
                self.commands.append(
                    "no %(iptype)s prefix-list %(name)s permit %(iprange)s" % pItem
                )
            else:
                self.commands.append(
                    "%(iptype)s prefix-list %(name)s permit %(iprange)s" % pItem
                )

        if not newConf:
            return
        for iptype, pdict in newConf.get("prefix_list", {}).items():
            for iprange, prefDict in pdict.items():
                for prefName, prefState in prefDict.items():
                    normIP = normalizeIPAddress(iprange)
                    out = {"iptype": iptype, "name": prefName, "iprange": iprange}
                    if normIP in parser.running_config.get("prefix-list", {}).get(
                            iptype, {}
                    ).get(prefName, {}):
                        if prefState == "absent":
                            genCmd(out, noCmd=True)
                    elif prefState == "present":
                        genCmd(out)

    def _genRouteMap(self, parser, newConf):
        """Generate Route-map commands."""

        def genCmd(pItem, noCmd=False):
            if noCmd:
                self.commands.append("no route-map %(name)s permit %(permit)s" % pItem)
            else:
                self.commands.append("route-map %(name)s permit %(permit)s" % pItem)
                self.commands.append(
                    " match %(iptype)s address prefix-list %(match)s" % pItem
                )
                # To secure from link local, SENSE uses only it's own predefined routes
                # and we should use only global. Using link-local will not work.
                if pItem["name"].endswith("mapin") and pItem["iptype"] == "ipv6":
                    self.commands.append(
                        " set %(iptype)s next-hop prefer-global" % pItem
                    )

        if not newConf:
            return
        for iptype, rdict in newConf.get("route_map", {}).items():
            for rMapName, rMapPrios in rdict.items():
                for prio, rNames in rMapPrios.items():
                    for rName, rState in rNames.items():
                        out = {
                            "iptype": iptype,
                            "permit": str(prio),
                            "name": rMapName,
                            "match": rName,
                        }
                        if out["match"] in parser.running_config.get(
                                "route-map", {}
                        ).get(out["name"], {}).get(out["permit"], {}):
                            if rState == "absent":
                                genCmd(out, True)
                        elif rState == "present":
                            genCmd(out)

    def _genBGP(self, parser, newConf):
        if not newConf:
            return
        senseasn = newConf.get("asn", None)
        if not senseasn:
            return
        runnasn = parser.running_config.get("bgp", {}).get("asn", None)
        if not runnasn:
            return
        if int(senseasn) != int(runnasn):
            msg = f"Running ASN != SENSE ASN ({runnasn} != {senseasn})"
            raise Exception(msg)
        # Append only if any new commands are added.
        self.commands.append(f"router bgp {senseasn}")
        for key in ["ipv6", "ipv4"]:
            for netw, netstate in newConf.get(f"{key}_network", {}).items():
                netwNorm = normalizeIPAddress(netw.split("/")[0])
                if (
                        netwNorm
                        in parser.running_config.get("bgp", {})
                        .get("address-family", {})
                        .get(key, {})
                        .get("network", {})
                        and netstate == "present"
                ):
                    continue
                # At this point it is not defined
                if netstate == "present":
                    # Add it
                    self.commands.append(f" address-family {key} unicast")
                    self.commands.append(f"  network {netw}")
                    self.commands.append(" exit-address-family")
                # Absent... TODO:
                # We need a flag passed via ansible config which allows removal
                # In case it is used in prod - we dont want to remove (as it might break routing)
            for neighIP, neighDict in newConf.get("neighbor", {}).get(key, {}).items():
                ipNorm = normalizeIPAddress(neighIP.split("/")[0])
                if ipNorm in parser.running_config.get("bgp", {}).get("neighbor", {}):
                    if neighDict["state"] == "absent":
                        self.commands.append(f" address-family {key} unicast")
                        self.commands.append(f"  no neighbor {ipNorm} remote-as {neighDict['remote_asn']}")
                        continue
                elif neighDict["state"] == "present":
                    # It is present in new config, but not present on router. Add it
                    self.commands.append(f" address-family {key} unicast")
                    self.commands.append(f"  neighbor {ipNorm} remote-as {neighDict['remote_asn']}")
                    # Adding remote-as will exit address family. Need to enter it again
                    self.commands.append(f" address-family {key} unicast")
                    self.commands.append(f"  neighbor {ipNorm} activate")
                    self.commands.append(f"  neighbor {ipNorm} soft-reconfiguration inbound")
                    for rtype in ["in", "out"]:
                        for rName, rState in (
                                neighDict.get("route_map", {}).get(rtype, {}).items()
                        ):
                            if rState == "present":
                                self.commands.append(f"  neighbor {ipNorm} route-map {rName} {rtype}")
                            elif rState == "absent":
                                self.commands.append(f"  no neighbor {ipNorm} route-map {rName} {rtype}")
                    self.commands.append(" exit-address-family")
        if len(self.commands) == 1:
            # means only router to configure. Skip it.
            self.commands = []
        return

    def generateCommands(self, parser, newConf):
        """Check new conf with running conf and generate commands
        for missing router config commands"""
        self._genPrefixList(parser, newConf)
        self._genRouteMap(parser, newConf)
        self._genBGP(parser, newConf)
        if self.commands:
            sendviaStdIn(f"sudo {vtyshcmd}", ["configure"] + self.commands)


class Main:
    """Main Frr Class"""

    def __init__(self):
        self.args = None
        self.frrAPI = FrrCmd()
        self.vtyshparser = vtyshParser()
        self.vtyConf = vtyshConfigure()
        self.logger = CustomLogger(logService="Main")

    def execute(self):
        """Main execute"""
        senseconfig = loadJson(self.args["config"])
        self.logger.info(f"SENSE Config: {senseconfig}")
        self.applyVlanConfig(senseconfig.get("INTERFACE", {}))
        self.applyBGPConfig(senseconfig.get("BGP", {}))

    def parseArgs(self, inFile):
        """Parse Args from input file"""
        if not os.path.isfile(inFile):
            self.logger.error("Input File from param does not exist on Device.")
            raise Exception("Input File from param does not exist on Device.")
        params = {"debug": r"frr_debug=(\S+)", "config": r"frr_config=(\S+)"}
        args = {}
        with open(inFile, "r", encoding="utf-8") as fd:
            tmptxt = fd.read()
            for key, reg in params.items():
                match = re.search(reg, tmptxt, re.M)
                if match:
                    args[key] = match[1]
        return args

    def applyVlanConfig(self, sensevlans):
        """Loop via sense vlans and check with frr vlans config"""
        for key, val in sensevlans.items():
            tmpKey = key.split(" ")
            if len(tmpKey) == 1:
                tmpD = {"vlan": "".join(key), "vlanid": key[4:]}
            else:
                tmpD = {"vlan": "".join(tmpKey), "vlanid": tmpKey[1]}
            tmpD["interface"] = list(val.get("tagged_members", {}).keys())[0]
            # Vlan ADD/Remove
            if val["state"] == "present":
                self.frrAPI.addVlan(**tmpD)
            if val["state"] == "absent":
                self.frrAPI.delVlan(**tmpD)
                continue
            for ipkey in ["ipv6_address", "ipv4_address"]:
                for ipval, ipstate in val.get(ipkey, {}).items():
                    tmpD["ip"] = normalizeIPAddress(ipval)
                    if ipstate == "present":
                        self.frrAPI.addIP(**tmpD)
                    if ipstate == "absent":
                        self.frrAPI.delIP(**tmpD)

    def applyBGPConfig(self, bgpconfig):
        """Generate BGP Commands and apply to Router (vtysh)"""
        self.vtyshparser.getConfig()
        self.vtyConf.generateCommands(self.vtyshparser, bgpconfig)

    def main(self):
        """Main run"""
        exitCode = 0
        try:
            if len(sys.argv) != 2:
                self.logger.error(f"Issue with passed arguments. Input: {sys.argv}")
                raise Exception(f"Issue with passed arguments. Input: {sys.argv}")
            self.args = self.parseArgs(sys.argv[1])
            if not self.args.get("config", None):
                self.logger.error(f"Issue with parsing input config. Input: {sys.argv}")
                raise Exception(f"Issue with parsing input config. Input: {sys.argv}")
            self.execute()
        except Exception as ex:
            self.logger.error(f"Exception: {ex}")
            exitCode = 1
        finally:
            self.logger.info(f"Run finished. Exit: {exitCode}")
            stdout = self.logger.getRunContent()
            self.logger.deleteRunContent()
            return exitCode, stdout


if __name__ == "__main__":
    main = Main()
    mainexitCode, mainstdout = main.main()
    changed = "ok" if mainexitCode == 0 else "failed"
    print(json.dumps({"changed": changed, "rc": mainexitCode, "stdout": "\n".join(mainstdout)}))
    sys.exit(mainexitCode)
