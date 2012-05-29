#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
from psl import psl

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
query_parser.add_argument("--passwd",nargs=1,help="password",required=True)
query_parser.add_argument("query",nargs="+",help="What to query for",choices=['ip','mac','model','gateway','netmask']);

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
set_parser.add_argument("--dhcp",nargs=1,help="DHCP?",choices=["on","off"])

args = parser.parse_args()
interface=args.interface[0]
#print interface

g = psl(interface)
if (args.debug):
  g.setDebugOutput()
if args.operation=="discover":
  print "Searching for ProSafe Plus Switches ...\n"
  g.discover()

if args.operation=="reboot":
  print "Rebooting Switch...\n";
  cmd={g.CMD_PASSWORD:args.passwd[0],
       g.CMD_REBOOT:True}
  g.transmit(cmd,pack_mac(args.mac[0]),g.transfunc)

if args.operation=="factory-reset":
  print "Reseting Switch to factory defaults...\n";
  cmd={g.CMD_PASSWORD:args.passwd[0],
       g.CMD_FACTORY_RESET:True}
  g.transmit(cmd,pack_mac(args.mac[0]),g.transfunc)

if args.operation=="passwd":
  print "Changing Password...\n";
  g.passwd(pack_mac(args.mac[0]),args.old[0],args.new[0],g.transfunc)

if args.operation=="set":
  print "Changing Values..\n"
  cmd={g.CMD_PASSWORD:args.passwd[0]}
  if (args.ip):
      cmd[g.CMD_IP]=args.ip[0]
  if (args.dhcp):
      cmd[g.CMD_DHCP]=(args.dhcp[0]=="on")
  if (args.name):
      cmd[g.CMD_NAME]=args.name[0]

  g.transmit(cmd,pack_mac(args.mac[0]),g.transfunc)

if args.operation=="query":
  print "Query Values..\n";
  #cmd={g.CMD_PASSWORD:args.passwd[0]}
  cmd=[]
  for q in args.query:
    if (q=="ip"):
      cmd.append(g.CMD_IP)
    if (g=="name"):
      cmd.append(g.CMD_NAME)
  g.query(cmd,g.transfunc)
    