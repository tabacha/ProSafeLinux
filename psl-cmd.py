#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import sys
from psl import ProSafeLinux
import psl_typ
g = ProSafeLinux()


parser = argparse.ArgumentParser(description='Manage Netgear ProSafe Plus switches under linux.')
parser.add_argument("--interface", nargs=1, help="Interface",default=["eth0"])
parser.add_argument("--debug", help="Debug output", action='store_true')
subparsers = parser.add_subparsers(help='operation',dest="operation")

discover_parser=subparsers.add_parser('discover', help='Find all switches in all subnets')

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


set_parser = subparsers.add_parser("set", help="Set values to the switch")
set_parser.add_argument("--mac", nargs=1,
    help="Hardware adresse of the switch", required=True)
set_parser.add_argument("--passwd", nargs=1, help="password", required=True)

for cmd in g.get_setable_cmds():
    if isinstance(cmd, psl_typ.PslTypAction):
        set_parser.add_argument("--" + cmd.get_name(),
            dest=cmd.get_name(), action='store_true')

    else:
        if isinstance(cmd, psl_typ.PslTypBoolean):
            set_parser.add_argument("--" + cmd.get_name(), nargs=1,
                choices=["on", "off"])
        else:
            set_parser.add_argument("--" + cmd.get_name(), nargs=1)

args = parser.parse_args()
interface = args.interface[0]

g.bind(interface)


def discover():
    print "Searching for ProSafe Plus Switches ...\n"
    g.discover()


def set():
    cmds = {ProSafeLinux.CMD_PASSWORD: args.passwd[0]}
    for cmd in g.get_setable_cmds():
        if vars(args)[cmd.get_name()] is not None:
            if isinstance(cmd, psl_typ.PslTypAction):
                if vars(args)[cmd.get_name()]:
                    cmds[cmd] = True
            else:
                if isinstance(cmd, psl_typ.PslTypBoolean):
                    cmds[cmd] = (vars(args)[cmd.get_name()][0] == "on")
                else:
                    cmds[cmd] = vars(args)[cmd.get_name()][0]

    if ProSafeLinux.CMD_DHCP in cmds:
        if cmds[ProSafeLinux.CMD_DHCP]:
            if ((ProSafeLinux.CMD_IP in cmds) or
                (ProSafeLinux.CMD_GATEWAY in cmds) or
                (ProSafeLinux.CMD_NETMASK in cmds)):
                print "When dhcp=on, no ip,gateway nor netmask is allowed"
                return
        else:
            if (not((ProSafeLinux.CMD_IP in cmds) and
              (ProSafeLinux.CMD_GATEWAY in cmds) and
              (ProSafeLinux.CMD_NETMASK in cmds))):
                print "When dhcp=off, specify ip,gateway and netmask"
                return
    else:
        if ((ProSafeLinux.CMD_IP in cmds) or
          (ProSafeLinux.CMD_GATEWAY in cmds) or
          (ProSafeLinux.CMD_NETMASK in cmds)):
            print "Use dhcp on,ip,gateway and netmask option together"
            return

    print "Changing Values..\n"
    g.transmit(cmds, args.mac[0], g.transfunc)


def query():
    print "Query Values..\n"
    if not(args.passwd == None):
        login = {g.CMD_PASSWORD: args.passwd[0]}
        g.transmit(login, args.mac[0], g.transfunc)
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



cmdHash = {
    "discover": discover,
    "set": set,
    "query": query,
    "query_raw": query_raw,
}

if (args.debug):
    g.set_debug_output()

if args.operation in cmdHash:
    cmdHash[args.operation]();
else:
    print "ERROR: operation not found!"
