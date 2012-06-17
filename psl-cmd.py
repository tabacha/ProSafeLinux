#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import sys
from psl import ProSafeLinux
import psl_typ
g = ProSafeLinux()


parser = argparse.ArgumentParser(description='Manage Netgear ProSafe Plus switches under linux.')
parser.add_argument("--interface",nargs=1,help="Interface",default=["eth0"])
parser.add_argument("--debug",help="Debug output",action='store_true')
subparsers = parser.add_subparsers(help='operation',dest="operation")

discover_parser=subparsers.add_parser('discover', help='Find all switches in all subnets')
passwd_parser=subparsers.add_parser("passwd",help="Change Password of a switch")
passwd_parser.add_argument("--mac",nargs=1,help="Hardware adresse of the switch",required=True)
passwd_parser.add_argument("--old",nargs=1,help="old password",required=True)
passwd_parser.add_argument("--new",nargs=1,help="new password",required=True)

query_parser=subparsers.add_parser("query",help="Query values from the switch")
query_parser.add_argument("--mac",nargs=1,help="Hardware adresse of the switch",required=True)
query_parser.add_argument("--passwd",nargs=1,help="password")
ch=[]
for cmd in g.get_query_cmds():
    ch.append(cmd.get_name())
ch.append("all")
query_parser.add_argument("query",nargs="+",help="What to query for",choices=ch);

query_parser=subparsers.add_parser("query_raw",help="Query raw values from the switch")
query_parser.add_argument("--mac",nargs=1,help="Hardware adresse of the switch",required=True)
query_parser.add_argument("--passwd",nargs=1,help="password")

reboot_parser=subparsers.add_parser("reboot",help="Reboot the switch")
reboot_parser.add_argument("--mac",nargs=1,help="Hardware adresse of the switch",required=True)
reboot_parser.add_argument("--passwd",nargs=1,help="password",required=True)

reset_parser=subparsers.add_parser("factory-reset",help="Reset the switch")
reset_parser.add_argument("--mac",nargs=1,help="Hardware adresse of the switch",required=True)
reset_parser.add_argument("--passwd",nargs=1,help="password",required=True)

set_parser=subparsers.add_parser("set",help="Set values to the switch")
set_parser.add_argument("--mac",nargs=1,help="Hardware adresse of the switch",required=True)
set_parser.add_argument("--passwd",nargs=1,help="password",required=True)
set_parser.add_argument("--ip",nargs=1,help="Change IP")
set_parser.add_argument("--name",nargs=1,help="Change Name")
set_parser.add_argument("--gateway",nargs=1,help="Default Gateway")
set_parser.add_argument("--netmask",nargs=1,help="Netmask")
set_parser.add_argument("--dhcp",nargs=1,help="DHCP?",choices=["on","off"])
set_parser.add_argument("--reset-traffic-statistic",dest="resettraffictstatistic",action='store_true');

args = parser.parse_args()
interface=args.interface[0]
#print interface

g.bind(interface)

def discover():
    print "Searching for ProSafe Plus Switches ...\n"
    g.discover()

def reboot():
    print "Rebooting Switch...\n";
    cmd={g.CMD_PASSWORD:args.passwd[0],
         g.CMD_REBOOT:True}
    g.transmit(cmd,args.mac[0],g.transfunc)

def factoryReset():
    print "Reseting Switch to factory defaults...\n";
    cmd={g.CMD_PASSWORD:args.passwd[0],
         g.CMD_FACTORY_RESET:True}
    g.transmit(cmd,args.mac[0],g.transfunc)
if args.operation=="passwd":
    print "Changing Password...\n";
    g.passwd(args.mac[0],args.old[0],args.new[0],g.transfunc)

def set():
    cmd={ProSafeLinux.CMD_PASSWORD:args.passwd[0]}

    if (args.ip):
        cmd[ProSafeLinux.CMD_IP]=args.ip[0]

    if (args.dhcp):
        cmd[ProSafeLinux.CMD_DHCP]=(args.dhcp[0]=="on")

    if (args.name):
        cmd[ProSafeLinux.CMD_NAME]=args.name[0]

    if (args.gateway):
        cmd[ProSafeLinux.CMD_GATEWAY]=args.gateway[0]

    if (args.netmask):
        cmd[ProSafeLinux.CMD_NETMASK]=args.netmask[0]

    if (args.resettraffictstatistic):
        cmd[ProSafeLinux.CMD_RESET_PORT_STAT]=True

    if ProSafeLinux.CMD_DHCP in cmd:
        if cmd[ProSafeLinux.CMD_DHCP]:
            if (ProSafeLinux.CMD_IP in cmd) or (ProSafeLinux.CMD_GATEWAY in cmd) or (ProSafeLinux.CMD_NETMASK in cmd):
                print "When dhcp=on, no ip,gateway nor netmask is allowed"
                return
        else:
            if (not((ProSafeLinux.CMD_IP in cmd) and (ProSafeLinux.CMD_GATEWAY in cmd) and (ProSafeLinux.CMD_NETMASK in cmd))):
                print "When dhcp=off, you have to specify ip,gateway and netmask"
                return
    else:
        if (ProSafeLinux.CMD_IP in cmd) or (ProSafeLinux.CMD_GATEWAY in cmd) or (ProSafeLinux.CMD_NETMASK in cmd):
            print "To change network settings use dhcp,ip,gateway and netmask option together"
            return

    print "Changing Values..\n"
    g.transmit(cmd,args.mac[0],g.transfunc)

def query():
    print "Query Values..\n";
    if not(args.passwd == None):
        login={g.CMD_PASSWORD:args.passwd[0]}
        g.transmit(login,args.mac[0],g.transfunc)
    cmd=[]
    for q in args.query:
        if q == "all":
            for k in g.get_query_cmds():
                if ((k!=ProSafeLinux.CMD_VLAN_ID) and (k!=ProSafeLinux.CMD_VLAN802_ID)):
                    cmd.append(k)
        else:
            c=g.get_cmd_by_name(q)
            cmd.append(c)
    g.query(cmd,args.mac[0],g.storefunc)
    for key in g.outdata.keys():
        if isinstance(key, psl_typ.PslTyp):
            key.print_result(g.outdata[key])
        else:
            if args.debug:
                print "-%-29s%s" %(key,g.outdata[key])

def query_raw():
    print "QUERY DEBUG RAW"
    if not(args.passwd == None):
        login={g.CMD_PASSWORD:args.passwd[0]}
        g.transmit(login,args.mac[0],g.transfunc)
    i=0x0001
    while (i<ProSafeLinux.CMD_END.get_id()):
        cmd=[]
        cmd.append(psl_typ.PslTypHex(i,"Command %d"%i))
        try:
            g.query(cmd,args.mac[0],g.rec_raw)
            found=None
            for c in g.outdata.keys():
                if (isinstance(c,psl_typ.PslTyp)):
                    if c.get_id()==i:
                        found=c

            if found is None:
                print "NON:%04x:%-29s:%s" % (i,"",g.outdata["raw"])
            else:
                print "RES:%04x:%-29s:%s " %(i,g.outdata[found],g.outdata["raw"])
            if args.debug:
                for key in g.outdata.keys():
                    print "%x-%-29s%s" %(i,key,g.outdata[key])
        except (KeyboardInterrupt,SystemExit):
            raise
        except:
            print "ERR:%04x:%s" %(i,sys.exc_info()[1])
        i=i+1



cmdHash={
    "reboot":reboot,
    "discover":discover,
    "factory-reset":factoryReset,
    "set":set,
    "query":query,
    "query_raw":query_raw,
}

if (args.debug):
    g.set_debug_output()

if args.operation in cmdHash:
    cmdHash[args.operation]();
else:
    print "ERROR: operation not found!"
