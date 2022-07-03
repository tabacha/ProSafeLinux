# -*- coding: utf-8 -*-
"Base Types for ProSafeLinux Class"

import binascii
import struct

class PslError:
    "Error class to map error codes to descriptions"
    def __init__(self, code, desc):
        "constructor"
        self.code = code
        self.desc = desc

    def get_code(self):
        "error code"
        return self.code

    def get_desc(self):
        "human-readable error description"
        return self.desc


class PslTyp:
    "Base type every other type is inherited by this"
    def __init__(self, cmd_id, name):
        "constructor"
        self.cmd_id = cmd_id
        self.name = name

    def get_id(self):
        "id of the command used by the switch to identify the command"
        return self.cmd_id

    def get_name(self):
        "name used by humans to identify the command"
        return self.name

    def pack_py(self, value):
        "pack a value to a represenation used by the switch"
        raise NotImplementedError

    def unpack_py(self, value):
        "unpack a switch value to a represenation used by the programm"
        raise NotImplementedError

    def pack_cmd(self, value):
        "pack something given from the cmd line"
        raise NotImplementedError

    def unpack_cmd(self, value):
        "unpack something given from the cmd line"
        raise NotImplementedError

    def print_result(self, value):
        "print a result for a query action"
        print("%-30s%s" % (self.get_name().capitalize(), value))

    def is_setable(self):
        "can this command be set like name (not like firmware version)"
        return False

    def is_queryable(self):
        "can the command be queryed like name (not like reboot switch)"
        return True

    def get_choices(self):
        "if there is more than one choice you can query it here"
        return None

    def get_num_args(self):
        "Number of arguments needed to set"
        return 1

    def get_metavar(self):
        "argparse metavar to set"
        return None

    def get_set_type(self):
        "argparse type to set"
        return None

    def get_set_help(self):
        "argparse help argument for set operation"
        return None

    def allow_multiple(self):
        "can this command be set multiple times in one transaction"
        return self.get_num_args() > 1

###############################################################################


class PslTypString(PslTyp):
    "A String typ line name"
    def pack_py(self, value):
        return value.encode()

    def unpack_py(self, value):
        return value.decode()

    def pack_cmd(self, value):
        return value.encode()

    def unpack_cmd(self, value):
        return value.decode()

    def is_setable(self):
        return True


###############################################################################


class PslTypStringQueryOnly(PslTypString):
    "a string type which can only be queried but not changed like firmware ver."
    def is_setable(self):
        return False


###############################################################################
class PslTypPassword(PslTypString):
    "a password can be set, but not queried"
    def __init__(self, cmd_id, name, setable):
        PslTypString.__init__(self, cmd_id, name)
        self.setable = setable

    def is_queryable(self):
        return False

    def is_setable(self):
        return self.setable

################################################################################


class PslTypBoolean(PslTyp):
    " A boolean type, like dhcp on or off"
    def pack_py(self, value):
        if (value):
            return struct.pack(">b", 0x01)
        else:
            return struct.pack(">b", 0x00)

    def unpack_py(self, value):
        if len(value)==1:
            numval = struct.unpack(">b", value)[0]
        else:
            numval = struct.unpack(">h",value)[0]
        return (numval == 0x01)

    def pack_cmd(self, value):
        return self.pack_py(value.lowercase == "on")

    def unpack_cmd(self, value):
        if (self.unpack_py(value)):
            return "on"
        else:
            return "off"

    def is_setable(self):
        return True

    def get_choices(self):
        return ["on", "off"]


###############################################################################


class PslTypFiltering(PslTyp):
    " Broadcast filtering, like a boolean but 0x00 and 0x03"
    def pack_py(self, value):
        if (value):
            return struct.pack(">b", 0x03)
        else:
            return struct.pack(">b", 0x00)

    def unpack_py(self, value):
        numval = struct.unpack(">b", value)[0]
        return (numval == 0x03)

    def pack_cmd(self, value):
        return self.pack_py(value.lowercase == "on")

    def unpack_cmd(self, value):
        if (self.unpack_py(value)):
            return "on"
        else:
            return "off"

    def is_setable(self):
        return True

    def get_choices(self):
        return ["on", "off"]


###############################################################################
class PslTypDHCP(PslTypBoolean):
    "DHCP"
# we already have that in base PslTypBoolean class, haven't we ?
#    def pack_py(self, value):
#        if (value):
#            # DHCP on
#            return struct.pack(">b", 0x01)
#        else:
#            return struct.pack(">b", 0x00)

###############################################################################


class PslTypAction(PslTypBoolean):
    "An action like reset or reboot switch"
    def pack_py(self, value):
        return struct.pack(">b", 0x01)

    def is_queryable(self):
        return False

    def is_setable(self):
        return True

###############################################################################


class PslTypMac(PslTyp):
    "the mac address"
    def pack_py(self, val):
        if (len(val) == 17):
            return binascii.unhexlify(val[0:2] + val[3:5] + val[6:8] +
                                      val[9:11] + val[12:14] + val[15:17])
        if (len(val) == 12):
            return binascii.unhexlify(val)
        raise "unkown mac format=" + val

    def unpack_py(self, value):
        mac = binascii.hexlify(value)
        mac = mac.decode()  # binascii.hexlify() yields a byte list in Python 3
        return (mac[0:2] + ":" + mac[2:4] + ":" + mac[4:6] + ":" + mac[6:8] +
               ":" + mac[8:10] + ":" + mac[10:12])

    def pack_cmd(self, value):
        return self.pack_py(value)

    def unpack_cmd(self, value):
        return self.unpack_py(value)

################################################################################


class PslTypIpv4(PslTyp):
    "IPv4 adrresss, gateway or netmask"
    def pack_py(self, value):
        adr = value.split(".")
        if len(adr)!= 4:
            raise ValueError("IP address wrong format %s" % value)
        for i in range(4):
            try:
                num = int(adr[i])
            except ValueError:
                raise ValueError("IP address wrong format %s (String?)" % value)
            if num > 255:
                raise ValueError("IP address wrong format %s (>255)" % value)
            if num < 0:
                raise ValueError("IP address wrong format %s (<0)" % value)
        return struct.pack(">BBBB", int(adr[0]), int(adr[1]), int(adr[2]),
                int(adr[3]))

    def unpack_py(self, value):
        adr = struct.unpack(">BBBB", value)
        return "%d.%d.%d.%d" % (adr[0], adr[1], adr[2], adr[3])

    def pack_cmd(self, value):
        return self.pack_py(value)

    def unpack_cmd(self, value):
        return self.unpack_py(value)

    def is_setable(self):
        return True


################################################################################

class PslTypHex(PslTyp):
    "just decode to hex"
    def pack_py(self, value):
        return binascii.unhexlify(value)

    def unpack_py(self, value):
        return binascii.hexlify(value).decode()

    def pack_cmd(self, value):
        return self.pack_py(value)

    def unpack_cmd(self, value):
        return self.unpack_py(value)

################################################################################

class PslTypDec(PslTyp):
    "just decode to decimal"
    def pack_py(self, value):
        return binascii.unhexlify(value)

    def unpack_py(self, value):
        # Convert bytes to a hex string then to a decimal integer
        # This allows us to convert a big-endian value of unknown length
        return int(binascii.hexlify(value).decode(), 16)

    def pack_cmd(self, value):
        return self.pack_py(value)

    def unpack_cmd(self, value):
        return self.unpack_py(value)

################################################################################

class PslTypUnknown(PslTypHex):
    "Unknown Data"
    def unpack_cmd(self, value):
        return "Unknown: %s - %s" % (self.name, binascii.hexlify(value))


################################################################################


class PslTypHexNoQuery(PslTypHex):
    "not query hex"
    def is_queryable(self):
        return False

################################################################################


class PslTypEnd(PslTypHex):
    "the last cmd of an query is End"
    def is_setable(self):
        return False

    def is_queryable(self):
        return False

    def print_result(self, value):
        pass

################################################################################


class PslTypPortStatus(PslTyp):
    "Speed/flow control status per port"
    SPEED_NONE = 0x00
    SPEED_10MH = 0x01
    SPEED_10MF = 0x02
    SPEED_100MH = 0x03
    SPEED_100MF = 0x04
    SPEED_1G = 0x05

    speed_to_string = {
        SPEED_NONE: "Not conn.",
        SPEED_10MH: "10Mbit/s half",
        SPEED_10MF: "10Mbit/s",
        SPEED_100MH: "100Mbit/s half",
        SPEED_100MF: "100Mbit/s",
        SPEED_1G: "1Gbit/s"
        }

    def unpack_py(self, value):
        # Python 3 uses an array of bytes, Python 2 uses a string
        if type(value) is str:
            rtn = {
                "port": struct.unpack(">b", value[0])[0],
                "speed": struct.unpack(">b", value[1])[0],
                "flow": struct.unpack(">b", value[2])[0]
            }
        else:
            rtn = {
                "port": value[0],
                "speed": value[1],
                "flow": value[2]
            }
        return rtn

    def is_setable(self):
        return False

    def print_result(self, value):
        print("%-30s%4s%20s%15s" % ("Status:", "Port",
                                    "Speed", "Flow control"))

        # Make sure we have a list of values (even if it's just a list of one)
        if type(value) != list:
            value = [value]

        for row in value:
            speed = self.speed_to_string[row["speed"]]

            flow = "Enabled"
            if row["flow"] == 0:
                flow = "Disabled"

            print("%-30s%4d%20s%15s" % ("", row["port"], speed, flow))

    def unpack_cmd(self, value):
        return self.unpack_py(value)


################################################################################


class PslTypAdminPortStatus(PslTyp):
    "Max speed/flow control per port"
    SPEED_DISABLE = 0x00
    SPEED_AUTO = 0x01
    SPEED_10MH = 0x02
    SPEED_10MF = 0x03
    SPEED_100MH = 0x04
    SPEED_100MF = 0x05

    speed_to_string = {
        SPEED_DISABLE: "Disable",
        SPEED_AUTO: "Auto",
        SPEED_10MH: "10M half",
        SPEED_10MF: "10M",
        SPEED_100MH: "100M half",
        SPEED_100MF: "100M",
        }

    string_to_speed = {
        "DISABLE":SPEED_DISABLE,
        "AUTO":SPEED_AUTO,
        "10MH":SPEED_10MH,
        "10M":SPEED_10MF,
        "100MH":SPEED_100MH,
        "100M":SPEED_100MF,
    }

    def unpack_py(self, value):
        # Python 3 uses an array of bytes, Python 2 uses a string
        if type(value) is str:
            rtn = {
                "port": struct.unpack(">b", value[0])[0],
                "speed": struct.unpack(">b", value[1])[0],
                "flow": struct.unpack(">b", value[2])[0]
            }
        else:
            rtn = {
                "port": value[0],
                "speed": value[1],
                "flow": value[2]
            }

        return rtn

    def pack_py(self, value):
        port = int(value[0])
        speed = self.string_to_speed[value[1].upper()]
        flow = (value[2].lower() == "on")
        rtn = struct.pack(">bbb", port, speed, flow)
        return rtn

    def unpack_cmd(self, value):
        return self.unpack_py(value)

    def print_result(self, value):
        print("%-30s%4s%20s%15s" % ("Status:", "Port",
                                    "Speed", "Flow control"))

        # Make sure we have a list of values (even if it's just a list of one)
        if type(value) != list:
            value = [value]

        for row in value:
            speed = self.speed_to_string[row["speed"]]
            flow = "On"
            if row["flow"] == 0:
                flow = "Off"

            print("%-30s%4d%20s%15s" % ("", row["port"], speed, flow))

    def is_queryable(self):
        return True

    def is_setable(self):
        return True

    def get_num_args(self):
        return 3

    def get_metavar(self):
        return ("PORT", "SPEED", "FLOW")

    def get_set_help(self):
        out = "SPEED can be: NONE,AUTO,10MH,10M,100MH,100M, FLOW can be: ON, OFF"
        return out


################################################################################


class PslTypPortStat(PslTyp):
    "how many bytes are received/send on each port"
    def unpack_py(self, val):
        # Python 3 uses an array of bytes, Python 2 uses a string
        values = struct.unpack("!b6Q", val)
        rtn = {
            "port": values[0],
            "rec": values[1],
            "send": values[2],
            "pkt": values[3],
            "bcst": values[4],
            "mcst": values[5],
            "error": values[6]
        }
        return rtn

    def unpack_cmd(self, value):
        return self.unpack_py(value)


    def is_setable(self):
        return False

    def print_result(self, value):
        print("%-30s%4s%15s%15s%15s%15s%15s%15s" % ("Port Statistic:", "Port",
                                      "Rec.", "Send", "Packets",
                                      "Broadcast pkt", "Multicast pkt",
                                      "CRC errors"))

        # Make sure we have a list of values (even if it's just a list of one)
        if type(value) != list:
            value = [value]

        for row in value:
            print("%-30s%4d%15d%15d%15d%15d%15d%15d" % ("",
                                      row["port"], row["rec"],
                                      row["send"], row["pkt"],
                                      row["bcst"], row["mcst"],
                                      row["error"]))

################################################################################


class PslTypBandwidth(PslTyp):
    "limit bandwidth"
    SPEED_LIMIT_NONE = 0x0000
    SPEED_LIMIT_512K = 0x0001
    SPEED_LIMIT_1M = 0x0002
    SPEED_LIMIT_2M = 0x0003
    SPEED_LIMIT_4M = 0x0004
    SPEED_LIMIT_8M = 0x0005
    SPEED_LIMIT_16M = 0x0006
    SPEED_LIMIT_32M = 0x0007
    SPEED_LIMIT_64M = 0x0008
    SPEED_LIMIT_128M = 0x0009
    SPEED_LIMIT_256M = 0x000a
    SPEED_LIMIT_512M = 0x000b

    speed_to_string = {
        SPEED_LIMIT_NONE: " NONE ",
        SPEED_LIMIT_512K: "  0.5M",
        SPEED_LIMIT_1M: "  1.0M",
        SPEED_LIMIT_2M: "  2.0M",
        SPEED_LIMIT_4M: "  4.0M",
        SPEED_LIMIT_8M: "  8.0M",
        SPEED_LIMIT_16M: " 16.0M",
        SPEED_LIMIT_32M: " 32.0M",
        SPEED_LIMIT_64M: " 64.0M",
        SPEED_LIMIT_128M: "128.0M",
        SPEED_LIMIT_256M: "256.0M",
        SPEED_LIMIT_512M: "512.0M"
        }

    string_to_speed = {
        "NONE":SPEED_LIMIT_NONE,
        "512K":SPEED_LIMIT_512K,
        "1M":SPEED_LIMIT_1M,
        "2M":SPEED_LIMIT_2M,
        "4M":SPEED_LIMIT_4M,
        "8M":SPEED_LIMIT_8M,
        "16M":SPEED_LIMIT_16M,
        "32M":SPEED_LIMIT_32M,
        "64M":SPEED_LIMIT_64M,
        "128M":SPEED_LIMIT_128M,
        "256M":SPEED_LIMIT_256M,
        "512M":SPEED_LIMIT_512M

    }
    def unpack_py(self, value):
        # Python 3 uses an array of bytes, Python 2 uses a string
        if type(value) is str:
            rtn = {
                "port": struct.unpack(">b", value[0])[0],
                "limit": struct.unpack(">h", value[3::])[0],
                "rest": binascii.hexlify(value[1:3]),
            }
        else:
            rtn = {
                "port": value[0],
                "limit": struct.unpack(">h", value[3::])[0],
                "rest": binascii.hexlify(value[1:3]).decode(),
            }
        return rtn

    def pack_py(self, value):
        limit = self.string_to_speed[value[1]]
        rtn = struct.pack(">bbbh", int(value[0]), 0, 0, limit)
        return rtn

    def print_result(self, value):
        print("%-30s%4s%15s %s" % (self.get_name().capitalize(), "Port",
                                      "Limit", "FIXME"))

        # Make sure we have a list of values (even if it's just a list of one)
        if type(value) != list:
            value = [value]

        for row in value:
            print("%-30s%4d%15s %s " % ("",
                                        row["port"],
                                        self.speed_to_string[row["limit"]],
                                        row["rest"]))

    def unpack_cmd(self, value):
        return self.unpack_py(value)

    def is_setable(self):
        return True

    def get_num_args(self):
        return 2

    def get_metavar(self):
        return ("PORT", "LIMIT")

    def get_set_help(self):
        out = "LIMIT can be: NONE,512K,1M,2M,4M,16M,32M,64M,128M,256M,512M"
        return out

################################################################################


class PslTypVlanId(PslTyp):
    "Vlan ports are binary coded"
    BIN_PORTS = {1: 0x80,
                 2: 0x40,
                 3: 0x20,
                 4: 0x10,
                 5: 0x08,
                 6: 0x04,
                 7: 0x02,
                 8: 0x01
                 }

    def set_total_ports(self, total_ports):
        # Calculate number of bytes required to store bitmap of all ports
        self.total_ports = total_ports
        self.num_port_bytes = (total_ports + 7) // 8

    def unpack_ports(self, port_bitmap, start = 0, length = 0):
        if length == 0:
            length = len(port_bitmap) - start

        port_bitmap = port_bitmap[start:start + length]
        port_list = []
        base = 0

        # Bytes are a bitmap of the ports from left-to-right
        # (so most-significant bit in the first byte is port 1)
        for ports in struct.unpack("%uB" % len(port_bitmap), port_bitmap):
            for port in list(self.BIN_PORTS.keys()):
                if (ports & self.BIN_PORTS[port] > 0):
                    port_list.append(port + base)
            base += 8

        return port_list

    def pack_ports(self, ports):
        "helper method to pack ports to binary"
        port_list = [0] * self.num_port_bytes

        if ports == "":
            return port_list

        if type(ports) is not list:
            ports = ports.split(",")

        for port in ports:
            port = int(port)
            base = (port - 1) // 8

            if base < len(port_list):
                port_list[base] |= self.BIN_PORTS[((port - 1) % 8) + 1]
            else:
                raise ValueError("Port '{}' is out of range".format(port))

        # Return a packed structure here to allow compatibility with
        # Python2 that will not allow multiple tuples to be unpacked in one
        # line so the results from multple calls to 'pack_ports' cannot be
        # passed to struct.pack unless we return a single value here (and not
        # a tuple)
        return struct.pack("%uB" % len(port_list), *port_list)

    def unpack_py(self, value):
        out_ports = self.unpack_ports(value, 2)

        rtn = {
            "vlan_id": struct.unpack(">h", value[0:2])[0],
            "ports": out_ports
        }
        return rtn

    def pack_py(self, value):
        ports = self.pack_ports(value[1])
        return struct.pack(">h%us" % len(ports), int(value[0]), ports)

    def unpack_cmd(self, value):
        return self.unpack_py(value)

    def is_setable(self):
        return True

    def get_num_args(self):
        return 2

    def get_metavar(self):
        return ("VLAN_ID", "PORTS")

    def print_result(self, value):
        print("%-30s%7s %s" % (self.get_name().capitalize(), "VLAN_ID",
                                      "Ports"))

        # Make sure we have a list of values (even if it's just a list of one)
        if type(value) != list:
            value = [value]

        for row in value:
            print("%-30s%7d %s" % ("",
                                   int(row["vlan_id"]),
                                   ",".join([str(x) for x in row["ports"]])))

################################################################################


class PslTypVlan802Id(PslTypVlanId):
    "802Vlan is binary coded"

    def unpack_py(self, value):
        port_len = (len(value) - 1) // 2

        out_member_ports = self.unpack_ports(value, 2, port_len)
        out_tagged_ports = self.unpack_ports(value, 2 + port_len, port_len)

        rtn = {
            "vlan_id": struct.unpack(">h", value[0:2])[0],
            "member_ports":out_member_ports,
            "tagged_ports": out_tagged_ports
        }
        return rtn

    def pack_py(self, value):
        members = self.pack_ports(value[1])
        tagged = self.pack_ports(value[2])
        rtn = struct.pack(">h%us%us" % (len(members), len(tagged)), int(value[0]), members, tagged)
        return rtn

    def unpack_cmd(self, value):
        return self.unpack_py(value)

    def get_num_args(self):
        return 3

    def get_metavar(self):
        return ("VLAN_ID", "MEMBER_PORTS", "TAGGED_PORTS")

    def print_result(self, value):
        print("%-30s%7s %18s %18s" % (self.get_name().capitalize(), "VLAN_ID",
                                      "Member ports","Tagged ports"))

        # Make sure we have a list of values (even if it's just a list of one)
        if type(value) != list:
            value = [value]

        for row in value:
            print("%-30s%7d %18s %18s" % ("",
                    int(row["vlan_id"]),
                    ",".join([str(x) for x in row["member_ports"]]),
                    ",".join([str(x) for x in row["tagged_ports"]])))

################################################################################


class PslTypVlanPVID(PslTyp):
    "The PVID"
    def unpack_py(self, value):
        # Python 3 uses an array of bytes, Python 2 uses a string
        if type(value) is str:
            rtn = {
                "port": struct.unpack(">B", value[0])[0],
                "vlan_id": struct.unpack(">h", value[1:])[0]
            }
        else:
            rtn = {
                "port": value[0],
                "vlan_id": struct.unpack(">h", value[1:])[0]
            }
        return rtn

    def pack_py(self, value):
#        value = value.encode()
        rtn = struct.pack(">Bh", int(value[0]), int(value[1]))
        return rtn

    def unpack_cmd(self, value):
        return self.unpack_py(value)

    def is_setable(self):
        return True

    def get_num_args(self):
        return 2

    def get_metavar(self):
        return ("PORT","VLAN_ID")

    def get_set_type(self):
        return int

    def print_result(self, value):
        print("%-30s%4s %s" % (self.get_name().capitalize(), "Port",
                                      "VLAN_ID"))

        # Make sure we have a list of values (even if it's just a list of one)
        if type(value) != list:
            value = [value]

        for row in value:
            print("%-30s%4d %7d" % ("",
                                        row["port"],
                                        row["vlan_id"]))


    def get_set_help(self):
        return "an untagged package on PORT will get this VLAN_ID"


################################################################################

class PslTypDeleteVlan(PslTyp):
    "Delete vlan"
    def unpack_py(self, value):
        return struct.unpack(">h", value)[0]

    def pack_py(self, value):
        rtn = struct.pack(">h", int(value))
        return rtn

    def pack_cmd(self, value):
        return self.pack_py(value)

    def unpack_cmd(self, value):
        return self.unpack_py(value)

    def is_queryable(self):
        return False

    def is_setable(self):
        return True

    def get_num_args(self):
        return 1

    def allow_multiple(self):
        return True

################################################################################


class UnknownValueException(Exception):
    "Found something which I don't know"


class PslTypQosMode(PslTyp):
    "Quality of service is port_based or 802.1p"
    def unpack_py(self, value):
        # Python 3 uses an array of bytes, Python 2 uses a string
        if type(value) is str:
            val = struct.unpack(">B", value[0])[0]
        else:
            val = value[0]
        if (val == 0x01):
            return "port_based"
        if (val == 0x02):
            return "802.1p"
        return val

    def pack_py(self, value):
        if (value == "802.1p"):
            return struct.pack(">B", 0x02)
        if (value == "port_based"):
            return struct.pack(">B", 0x01)
        raise UnknownValueException("Unknown value %s" % value)

    def unpack_cmd(self, value):
        return self.unpack_py(value)

    def is_setable(self):
        return True

    def get_choices(self):
        return ["port_based","802.1p"]

################################################################################


class PslTypPortBasedQOS(PslTyp):
    "Port based quality of service"

    QOS_PRIORITY = {
      0x01:"HIGH",
      0x02:"MIDDLE",
      0x03:"NORMAL",
      0x04:"LOW"
     }
    def unpack_py(self, value):
        # Python 3 uses an array of bytes, Python 2 uses a string
        if type(value) is str:
            rtn = {
                "port": struct.unpack(">B", value[0])[0],
                "qos": self.QOS_PRIORITY[struct.unpack(">B", value[1:])[0]]
            }
        else:
            rtn = {
                "port": value[0],
                "qos": self.QOS_PRIORITY[struct.unpack(">B", value[1:])[0]]
            }
        return rtn

    def pack_py(self, value):
        qos = None
        for k in list(self.QOS_PRIORITY.keys()):
            val = self.QOS_PRIORITY[k]
            if val == value[1]:
                qos = k
        if qos == None:
            raise UnknownValueException("Unknown value %s" % value[1])
        return struct.pack(">BB", int(value[0]), qos)

    def unpack_cmd(self, value):
        return self.unpack_py(value)

    def is_setable(self):
        return True

    def get_num_args(self):
        return 2

    def get_metavar(self):
        return ("PORT","QOS")

    def get_set_help(self):
        return "QOS can be HIGH, MIDDLE, NORMAL, or LOW"

    def print_result(self, value):
        print("%-30s%4s %s" % (self.get_name().capitalize(), "Port",
                                      "Priority"))

        # Make sure we have a list of values (even if it's just a list of one)
        if type(value) != list:
            value = [value]

        for row in value:
            print("%-30s%4d %s" % ("",
                                   row["port"],
                                   row["qos"]))

################################################################################


class PslTypIGMPSnooping(PslTyp):
    "IGMP Snooping"
    def unpack_py(self, value):
        enabled = struct.unpack(">h", value[0:2])[0]
        if (enabled == 0):
            return None
        if (enabled == 0x0001):
            # VLAN Id
            return struct.unpack(">h", value[2:])[0]
        raise UnknownValueException("Unknown value %d" % enabled)

    def pack_py(self, value):
        if (value == "none"):
            return struct.pack(">hh", 0, 0)
        return struct.pack(">hh", 0x0001, int(value))

    def unpack_cmd(self, value):
        return self.unpack_py(value)

    def is_setable(self):
        return True


################################################################################


class PslTypVlanSupport(PslTyp):
    "VLAN Support can be none, port-, ip-, 802-port- or 802 ext-based"
    VLAN_NONE = 0x00
    VLAN_PORT_BASED = 0x01
    VLAN_ID_BASED = 0x02
    VLAN_8021Q_PORT_BASED = 0x03
    VLAN_8021Q_EXTENDED = 0x04
    id2str = {
        VLAN_NONE: "none",
        VLAN_PORT_BASED: "port",
        VLAN_ID_BASED: "id",
        VLAN_8021Q_PORT_BASED: "802.1q_id",
        VLAN_8021Q_EXTENDED: "802.1q_extended"
        }

    def unpack_py(self, value):
        # Python 3 uses an array of bytes, Python 2 uses a string
        if type(value) is str:
            support = struct.unpack(">b", value[0])[0]
        else:
            support = value[0]
        if support in self.id2str:
            return self.id2str[support]
        raise UnknownValueException("Unknown value %d" % support)

    def pack_py(self, value):
        found = None
        for key in self.id2str:
            if self.id2str[key] == value:
                found = key
        if found is None:
            raise UnknownValueException("Unknown value %s" % value)
        return struct.pack(">b", found)

    def unpack_cmd(self, value):
        return self.unpack_py(value)

    def is_setable(self):
        return True

    def get_choices(self):
        return list(self.id2str.values())

################################################################################


class PslTypPortMirror(PslTyp):
    "Port Mirroring"
    BIN_PORTS = {1: 0x80,
                 2: 0x40,
                 3: 0x20,
                 4: 0x10,
                 5: 0x08,
                 6: 0x04,
                 7: 0x02,
                 8: 0x01
                 }

    def set_total_ports(self, total_ports):
        # Calculate number of bytes required to store bitmap of all ports
        self.total_ports = total_ports
        self.num_port_bytes = (total_ports + 7) // 8

    def unpack_py(self, value):
        dst_port, fixme = struct.unpack(">BB", value[:2])
        # Remaining values are a bitmap of the source ports
        src_port_list = value[2:]
        out_src_ports = []

        base = 0

        # Bytes are a bitmap of the source ports from left-to-right
        # (so most-significant bit in the first byte is port 1)
        for src_ports in struct.unpack("%uB" % len(src_port_list), src_port_list):
            for port in list(self.BIN_PORTS.keys()):
                if (src_ports & self.BIN_PORTS[port] > 0):
                    out_src_ports.append(port + base)
            base += 8

        if dst_port == 0:
            return "No Port Mirroring has been set up"
        rtn = {
            "dst_port": dst_port,
            "fixme": fixme,
            "src_ports": out_src_ports,
        }
        return rtn

    def pack_py(self, value):
        dst_port = int(value[0])
        src_ports = [0] * self.num_port_bytes

        if dst_port != 0:
            if dst_port > self.total_ports:
                raise ValueError("Destination port '{}' is out of range".format(dst_port))

            port_list = value[1]

            # Convert comma-separated values into a list
            if type(port_list) is not list:
                port_list = port_list.split(",")

            for sport in port_list:
                sport = int(sport)
                idx = (sport - 1) // 8

                if sport >= 1 and sport <= self.total_ports:
                    src_ports[idx] |= self.BIN_PORTS[((sport - 1) % 8) + 1]
                else:
                    raise ValueError("Source port '{}' is out of range".format(sport))

        return struct.pack(">BB%uB" % len(src_ports), dst_port, 0, *src_ports)

    def unpack_cmd(self, value):
        return self.unpack_py(value)

    def is_setable(self):
        return True

    def get_num_args(self):
        return 2

    def get_metavar(self):
        return ("DST_PORT","SRC_PORTS")

    def get_set_help(self):
        return "SET DST_PORT and SRC_PORTS to 0 to disable"

################################################################################

class PslTypCableTest(PslTyp):

    def unpack_py(self, value):
        port, fixme = struct.unpack(">bb", value)

        rtn = {
            "port": port,
            "fixme": fixme,
        }
        return rtn

    def pack_py(self, value):
        return struct.pack(">BB", int(value), 1)

    def is_queryable(self):
        return False

    def is_setable(self):
        return True

    def get_num_args(self):
        return 1

    def get_metavar(self):
        return ("PORT")

    def get_set_type(self):
        return int

################################################################################

class PslTypCableTestResult(PslTyp):
    "Cable test"
    STATUS_OK            = 0x00
    STATUS_NO_CABLE      = 0x01
    STATUS_OPEN_CABLE    = 0x02
    STATUS_SHORT_CIRCUIT = 0x03
    STATUS_FIBRE_CABLE   = 0x04
    STATUS_SHORTED_CABLE = 0x05
    STATUS_UNKNOWN       = 0x06
    STATUS_CROSSTALK     = 0x07

    status_to_string = {
        STATUS_OK: "OK",
        STATUS_NO_CABLE: "No cable",
        STATUS_OPEN_CABLE: "Open cable",
        STATUS_SHORT_CIRCUIT: "Short circuit",
        STATUS_FIBRE_CABLE: "Fibre cable",
        STATUS_SHORTED_CABLE: "Shorted cable",
        STATUS_UNKNOWN: "Unknown",
        STATUS_CROSSTALK: "Crosstalk"
        }

    def unpack_py(self, value):
        port, status, dist = struct.unpack(">BII", value)
        rtn = {
            "port": port,
            "status": status,
            "dist": dist
        }
        return rtn

    def pack_py(self, value):
        return binascii.unhexlify("{:02x}".format(value[0]))

    def is_setable(self):
        return False

    def print_result(self, value):
        print(("%-30s%4s%20s%19s" % ("Cable status:", "Port",
                                   "Status", "Fault distance (m)")))

        # Make sure we have a list of values (even if it's just a list of one)
        if type(value) != list:
            value = [value]

        for row in value:
            print(("%-30s%4d%20s%19u" % ("", row["port"], self.status_to_string[row["status"]], row["dist"])))


    def unpack_cmd(self, value):
        return self.unpack_py(value)

################################################################################

class PslTypSerialNum(PslTyp):
    "switch's serial number"
    def unpack_py(self, val):
        values = struct.unpack("!B13sB6B", val)
        one = values[0]     # Should be 1
        zero = values[2]    # Should be zero (null-terminator?)
        fixup = values[3]   # Six bytes (??)

        return values[1].decode()

    def unpack_cmd(self, value):
        return self.unpack_py(value)

    def is_setable(self):
        return False

