#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
SENSE Frr Module, which is copied and called via Ansible from
SENSE Site-RM Resource Manager.
"""
import ast
import json
import os
import re
import shlex
import subprocess
import sys


def externalCommand(command):
    """Execute External Commands and return stdout and stderr."""
    command = shlex.split(command)
    with subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as proc:
        stdout, stderr = proc.communicate()
        exitCode = proc.wait()
        if exitCode != 0:
            raise Exception(
                f"{command} exited non-zero. Exit: {exitCode} Stdout: {stdout} Stderr: {stderr}"
            )
        return [stdout, stderr, exitCode]
    return ["", "", -1]


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

def listtostr(inlist):
    """List to Str conversation"""
    out = ""
    for line in inlist:
        out += f"{str(line)}\n"
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

class Main:
    """Main Frr Class"""
    def __init__(self):
        self.args = None
        self.module_stdout = []
        self.module_stderr = []
        self.rc = 0

    def log_out(self, out):
        """Log all output to stdout and stderr. Set RC code of command exit"""
        for line in out[0].decode("utf-8").split("\n"):
            self.module_stdout.append(line)
        for line in out[1].decode("utf-8").split("\n"):
            self.module_stderr.append(line)
        self.rc = out[2]

    def execute_ping(self, pingconf):
        """Execute ping command"""
        count = pingconf.get('count', 10)  # Default to 10
        timeout = pingconf.get('timeout', 5)  # Default to 5 seconds
        ipv4_address = pingconf.get('ipv4_address', '')
        ipv6_address = pingconf.get('ipv6_address', '')
        ping_type = pingconf.get('type', None)

        # Construct the ping command based on the type
        if ping_type == 'ipv4':
            address = ipv4_address
            ping_command = f"ping -c {count} -W {timeout} {address}"
        elif ping_type == 'ipv6':
            address = ipv6_address
            ping_command = f"ping6 -c {count} -W {timeout} {address}"
        else:
            raise ValueError("Unsupported type. Only 'ipv4' and 'ipv6' are supported.")
        # Execute command and get output
        try:
            out = externalCommand(ping_command)
        except Exception as ex:
            raise Exception(f"Failed execute command {ping_command}. Exception {ex}") from ex
        self.log_out(out)


    def execute_traceroute(self, traceconf):
        """Execute traceroute command"""
        ipv4_address = traceconf.get('ipv4_address', '')
        ipv6_address = traceconf.get('ipv6_address', '')
        trace_type = traceconf.get('type', 'ipv4')

        # Construct the traceroute command based on the type
        if trace_type == 'ipv4':
            address = ipv4_address
            traceroute_command = f"traceroute {address}"
        elif trace_type == 'ipv6':
            address = ipv6_address
            traceroute_command = f"traceroute6 {address}"
        else:
            raise ValueError("Unsupported type. Only 'ipv4' and 'ipv6' are supported.")
        # Execute command and get output
        try:
            out = externalCommand(traceroute_command)
        except Exception as ex:
            raise Exception(f"Failed execute command {traceroute_command}. Exception {ex}") from ex
        self.log_out(out)

    def execute(self, action):
        """Main execute"""
        senseconfig = loadJson(self.args[action])
        if action == "ping":
            self.module_stdout.append(f"Execute ping: {senseconfig.get('PING', None)}")
            self.execute_ping(senseconfig.get('PING', None))
        elif action == "traceroute":
            self.module_stdout.append(f"Execute traceroute: {senseconfig.get('TRACEROUTE', None)}")
            self.execute_traceroute(senseconfig.get('TRACEROUTE', None))
        else:
            self.module_stderr.append(f"Unknown action {action}")
            raise Exception(f"Unknown action {action}")

    def parseArgs(self, inFile):
        """Parse Args from input file"""
        if not os.path.isfile(inFile):
            raise Exception("Input File from param does not exist on Device.")
        params = {"debug": r"frr_debug=(\S+)",
                  "ping": r"frr_ping=(\S+)",
                  "traceroute": r"frr_traceroute=(\S+)"}
        args = {}
        with open(inFile, "r", encoding="utf-8") as fd:
            tmptxt = fd.read()
            for key, reg in params.items():
                match = re.search(reg, tmptxt, re.M)
                if match:
                    args[key] = match[1]
        return args

    def mainwrap(self):
        """Main wrapper for call"""
        if len(sys.argv) != 2:
            raise Exception(f"Issue with passed arguments. Input: {sys.argv}")
        self.args = self.parseArgs(sys.argv[1])
        action = None
        if self.args.get("ping", None):
            self.module_stdout.append(self.args["ping"])
            self.module_stderr.append(self.args["ping"])
            action = "ping"
        elif self.args.get("traceroute", None):
            self.module_stdout.append(self.args["traceroute"])
            self.module_stderr.append(self.args["traceroute"])
            action = "traceroute"
        else:
            self.module_stderr.append(f"Issue with parsing input config. Input: {sys.argv}")
            raise Exception(f"Issue with parsing input config. Input: {sys.argv}")
        self.execute(action)
    def main(self):
        """Main call executed by ansible"""
        try:
            self.mainwrap()
        except Exception as ex:
            self.module_stderr.append(f"Received exception running script. Ex: {ex}")
            self.rc = 1
        out = {'stdout': listtostr(self.module_stdout), 'stderr': listtostr(self.module_stderr), 'rc': self.rc, 'changed': False}
        print(json.dumps(out))


if __name__ == "__main__":
    main = Main()
    main.main()
    sys.exit(0)
