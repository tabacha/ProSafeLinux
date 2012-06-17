#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import binascii
import sys
from psl import psl
import psl_typ
g = psl()

query_cmds={
    "ip":psl.CMD_IP,
    "name":psl.CMD_NAME,
    "model":psl.CMD_MODEL,
    "mac":psl.CMD_MAC,
    "gateway":psl.CMD_GATEWAY,
    "dhcp":psl.CMD_DHCP,
    "netmask":psl.CMD_NETMASK,
    "firmware_version":psl.CMD_FIRMWAREV,
    "traffic-statistic":psl.CMD_PORT_STAT,
    "speed-statistic":psl.CMD_SPEED_STAT,
    "vlan_engine":psl.CMD_VLAN_SUPP,
    "vlan_id":psl.CMD_VLAN_ID,
    "vlan802_id":psl.CMD_VLAN802_ID, 
    "vlan_pvid":psl.CMD_VLANPVID,
    "qos_id":psl.CMD_QUALITY_OF_SERVICE,
    "port_qos":psl.CMD_PORT_BASED_QOS,
    "bandwith_limit_in":psl.CMD_BANDWITH_INCOMMING_LIMIT,
    "bandwith_limit_out":psl.CMD_BANDWITH_OUTGOING_LIMIT,
    "broadcast_filter":psl.CMD_BROADCAST_FILTER,
    "port_mirror":psl.CMD_PORT_MIRROR,
    "block_unkown_multicast":psl.CMD_BLOCK_UNKOWN_MULTICAST,
    "igmp_spoofing":psl.CMD_IGMP_SPOOFING,
    "fixme_2":psl.CMD_FIMXE2,
    "fixme_5":psl.CMD_FIMXE5,
    "fixme_c":psl.CMD_FIXMEC,	
    "fixme_e":psl.CMD_FIXMEF,
    "fixme_f":psl.CMD_FIXMEF,
    "number_of_ports":psl.CMD_NUMBER_OF_PORTS,
    "fixme_6800":psl.CMD_FIXME6800,
    "fixme_7400":psl.CMD_FIXME7400,
}

query_cmds_rev={}

for key in query_cmds: 
    value=query_cmds[key]
    query_cmds_rev[value]=key

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
for cmd in g.getQueryCmds():
    ch.append(cmd.getName())
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
    cmd={psl.CMD_PASSWORD:args.passwd[0]}

    if (args.ip):
        cmd[psl.CMD_IP]=args.ip[0]

    if (args.dhcp):
        cmd[psl.CMD_DHCP]=(args.dhcp[0]=="on")

    if (args.name):
        cmd[psl.CMD_NAME]=args.name[0]

    if (args.gateway):
        cmd[psl.CMD_GATEWAY]=args.gateway[0]

    if (args.netmask):
        cmd[psl.CMD_NETMASK]=args.netmask[0]

    if (args.resettraffictstatistic):
        cmd[psl.CMD_RESET_PORT_STAT]=True

    if psl.CMD_DHCP in cmd:
        if cmd[psl.CMD_DHCP]:
            if (psl.CMD_IP in cmd) or (psl.CMD_GATEWAY in cmd) or (psl.CMD_NETMASK in cmd):
                print "When dhcp=on, no ip,gateway nor netmask is allowed"
                return
        else:
            if (not((psl.CMD_IP in cmd) and (psl.CMD_GATEWAY in cmd) and (psl.CMD_NETMASK in cmd))): 
                print "When dhcp=off, you have to specify ip,gateway and netmask"
                return
    else:
        if (psl.CMD_IP in cmd) or (psl.CMD_GATEWAY in cmd) or (psl.CMD_NETMASK in cmd):
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
            for k in g.getQueryCmds():
                if ((k!=psl.CMD_VLAN_ID) and (k!=psl.CMD_VLAN802_ID)):
                    cmd.append(k)
        else:
            c=g.getCmdByName(q) 
            cmd.append(c)
    g.query(cmd,args.mac[0],g.storefunc)
    for key in g.outdata.keys():
        if isinstance(key, psl_typ.psl_typ):
            key.printResult(g.outdata[key])
        else:
            if args.debug:
                print "-%-29s%s" %(key,g.outdata[key])

def query_raw():
    print "QUERY DEBUG RAW"
    if not(args.passwd == None):
        login={g.CMD_PASSWORD:args.passwd[0]}
        g.transmit(login,args.mac[0],g.transfunc)
    i=0x0001
    while (i<psl.CMD_END):
        cmd=[]
        cmd.append(i)
        try:
            g.query(cmd,args.mac[0],g.rec_raw)    
            if i in g.outdata.keys():
                print "RES:%04x:%-29s:%s " %(i,g.outdata[i],g.outdata["raw"])
            else:
                print "NON:%04x:%-29s:%s" % (i,"",g.outdata["raw"])
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
    g.setDebugOutput()

if args.operation in cmdHash:
    cmdHash[args.operation]();
else:
    print "ERROR: operation not found!"