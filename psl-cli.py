#!/usr/bin/python
# -*- coding: utf-8 -*-
"Main Program executed by the user"

import argparse
import sys
from psl_class import ProSafeLinux
import psl_typ

# pylint: disable=W0613


def discover(args, switch):
    "Search for Switches"
    dhcpstr = ""
    print "Searching for ProSafe Plus Switches ...\n"
    data = switch.discover()
    if (data[switch.CMD_DHCP]):
        dhcpstr = " DHCP=on"
    print " * %s\t%s\t%s\t%s\t%s" % (data[switch.CMD_MAC],
                                     data[switch.CMD_IP],
                                     data[switch.CMD_MODEL],
                                     data[switch.CMD_NAME],
                                     dhcpstr)


# pylint: enable=W0613

def exploit(args, switch):
    "exploit in current (2012) fw, can set a a new password"
    switch.passwd_exploit(args.mac[0], args.new_password[0], switch.transfunc)
    
def set_switch(args, switch):
    "Set values on switch"
    cmds = {ProSafeLinux.CMD_PASSWORD: args.passwd[0]}
    for scmd in switch.get_setable_cmds():
        if vars(args)[scmd.get_name()] is not None:
            if isinstance(scmd, psl_typ.PslTypAction):
                if vars(args)[scmd.get_name()]:
                    cmds[scmd] = True
            else:
                if isinstance(scmd, psl_typ.PslTypBoolean):
                    cmds[scmd] = (vars(args)[scmd.get_name()][0] == "on")
                else:
                    if len(vars(args)[scmd.get_name()])==1:
                        cmds[scmd] = vars(args)[scmd.get_name()][0]
                    else:
                        cmds[scmd] = vars(args)[scmd.get_name()]


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
    switch.transmit(cmds, args.mac[0], switch.transfunc)


def query(args, switch):
    "query values form the switch"
    print "Query Values..\n"
    if not(args.passwd == None):
        login = {switch.CMD_PASSWORD: args.passwd[0]}
        switch.transmit(login, args.mac[0], switch.transfunc)
    query_cmd = []
    for qarg in args.query:
        if qarg == "all":
            for k in switch.get_query_cmds():
                if ((k != ProSafeLinux.CMD_VLAN_ID) and
                    (k != ProSafeLinux.CMD_VLAN802_ID)):
                    query_cmd.append(k)
        else:
            query_cmd.append(switch.get_cmd_by_name(qarg))
    switch.query(query_cmd, args.mac[0], switch.storefunc)
    for key in switch.outdata.keys():
        if isinstance(key, psl_typ.PslTyp):
            key.print_result(switch.outdata[key])
        else:
            if args.debug:
                print "-%-29s%s" % (key, switch. outdata[key])


def query_raw(args, switch):
    "get all values, even unkown"
    print "QUERY DEBUG RAW"
    if not(args.passwd == None):
        login = {switch.CMD_PASSWORD: args.passwd[0]}
        switch.transmit(login, args.mac[0], switch.transfunc)
    i = 0x0001
    while (i < ProSafeLinux.CMD_END.get_id()):
        query_cmd = []
        query_cmd.append(psl_typ.PslTypHex(i, "Command %d" % i))
        try:
            switch.query(query_cmd, args.mac[0], switch.rec_raw)
            found = None
            for qcmd in switch.outdata.keys():
                if (isinstance(qcmd, psl_typ.PslTyp)):
                    if qcmd.get_id() == i:
                        found = qcmd

            if found is None:
                print "NON:%04x:%-29s:%s" % (i, "", switch.outdata["raw"])
            else:
                print "RES:%04x:%-29s:%s " % (i, switch.outdata[found],
                    switch.outdata["raw"])
            if args.debug:
                for key in switch.outdata.keys():
                    print "%x-%-29s%s" % (i, key, switch.outdata[key])
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            print "ERR:%04x:%s" % (i, sys.exc_info()[1])
        i = i + 1


def main():
    "main program"
    cmd_funcs = {
        "discover": discover,
        "set": set_switch,
        "query": query,
        "query_raw": query_raw,
        "exploit": exploit,
    }

    switch = ProSafeLinux()
    parser = argparse.ArgumentParser(
        description='Manage Netgear ProSafe Plus switches under linux.')
    parser.add_argument("--interface", nargs=1, help="Interface",
        default=["eth0"])
    parser.add_argument("--debug", help="Debug output", action='store_true')
    subparsers = parser.add_subparsers(help='operation', dest="operation")

    subparsers.add_parser('discover', help='Find all switches in all subnets')
    
    exploit_parser = subparsers.add_parser("exploit",
       help="set a password without knowing the old one")
    exploit_parser.add_argument("--mac", nargs=1,
        help="Hardware adresse of the switch", required=True)
    exploit_parser.add_argument("--new_password", nargs=1,
        help="password",required=True)

    query_parser = subparsers.add_parser("query",
        help="Query values from the switch")
    query_parser.add_argument("--mac", nargs=1,
        help="Hardware adresse of the switch", required=True)
    query_parser.add_argument("--passwd", nargs=1, help="password")
    choices = []
    for cmd in switch.get_query_cmds():
        choices.append(cmd.get_name())
    choices.append("all")
    
    query_parser.add_argument("query", nargs="+", help="What to query for",
        choices=choices)

    query_parser = subparsers.add_parser("query_raw",
        help="Query raw values from the switch")
    query_parser.add_argument("--mac", nargs=1,
        help="Hardware adresse of the switch", required=True)
    query_parser.add_argument("--passwd", nargs=1,
        help="password")

    set_parser = subparsers.add_parser("set", help="Set values to the switch")
    set_parser.add_argument("--mac", nargs=1,
        help="Hardware adresse of the switch", required=True)
    set_parser.add_argument("--passwd", nargs=1, help="password", required=True)

    for cmd in switch.get_setable_cmds():
        if isinstance(cmd, psl_typ.PslTypAction):
            set_parser.add_argument("--" + cmd.get_name(),
                dest=cmd.get_name(), action='store_true')

        else:
            set_parser.add_argument("--" + cmd.get_name(), 
                nargs=cmd.get_num_args(),
                type=cmd.get_set_type(),
                help=cmd.get_set_help(),
                metavar=cmd.get_metavar(),
                choices=cmd.get_choices())

    args = parser.parse_args()
    interface = args.interface[0]

    switch.bind(interface)

    if (args.debug):
        switch.set_debug_output()

    if args.operation in cmd_funcs:
        cmd_funcs[args.operation](args, switch)
    else:
        print "ERROR: operation not found!"

main()
