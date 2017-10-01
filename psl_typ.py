# -*- coding: utf-8 -*-
"Base Types for ProSafeLinux Class"

import binascii
import struct

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
        value = value.split("\0", 1)[0]
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


class PslTypSpeedStat(PslTyp):
    "Speed statistic 10/100/1000 per port"
    SPEED_NONE = 0x00
    SPEED_10MH = 0x01
    SPEED_10ML = 0x02
    SPEED_100MH = 0x03
    SPEED_100ML = 0x04
    SPEED_1G = 0x05

    def unpack_py(self, value):
        # Python 3 uses an array of bytes, Python 2 uses a string
        if type(value) is str:
            rtn = {
                "port": struct.unpack(">b", value[0])[0],
                "speed": struct.unpack(">b", value[1])[0],
                "rest": binascii.hexlify(value[2:]),
            }
        else:
            rtn = {
                "port": value[0],
                "speed": value[1],
                "rest": binascii.hexlify(value[2:]).decode(),
            }
        return rtn

    def is_setable(self):
        return False

    def print_result(self, value):
        print("%-30s%4s%15s%10s" % ("Speed Statistic:", "Port",
                                    "Speed", "FIXME"))
        for row in value:
            speed = row["speed"]
            if speed == PslTypSpeedStat.SPEED_NONE:
                speed = "Not conn."
            if speed == PslTypSpeedStat.SPEED_10MH:
                speed = "10 Mbit/s H"
            if speed == PslTypSpeedStat.SPEED_10ML:
                speed = "10 Mbit/s L"
            if speed == PslTypSpeedStat.SPEED_100MH:
                speed = "100 Mbit/s H"
            if speed == PslTypSpeedStat.SPEED_100ML:
                speed = "100 Mbit/s L"
            if speed == PslTypSpeedStat.SPEED_1G:
                speed = "1 Gbit/s"
            print("%-30s%4d%15s%10s" % ("", row["port"], speed, row["rest"]))

    def unpack_cmd(self, value):
        return self.unpack_py(value)


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

    def unpack_py(self, value):
        ports = struct.unpack(">B", value[2:])[0]
        out_ports = []
        for port in list(self.BIN_PORTS.keys()):
            if (ports & self.BIN_PORTS[port] > 0):
                out_ports.append(port)
        rtn = {
            "vlan_id": struct.unpack(">h", value[0:2])[0],
            "ports": out_ports
        }
        return rtn
        
    def pack_port(self, ports):
        "helper method to pack ports to binary"
        rtn = 0
        if ports == "":
            return rtn
        for port in ports.split(","):
            rtn = rtn + self.BIN_PORTS[int(port)]
        return rtn

    def pack_py(self, value):
        ports = self.pack_port(value[1])
        rtn = struct.pack(">hB", int(value[0]), ports)
        return rtn

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
        for row in value:
            print("%-30s%7d %s" % ("",
                                   int(row["vlan_id"]),
                                   ",".join([str(x) for x in row["ports"]])))


################################################################################


class PslTypVlan802Id(PslTypVlanId):
    "802Vlan is binary coded"

    def unpack_py(self, value):
        # Python 3 uses an array of bytes, Python 2 uses a string
        if type(value) is str:
            tagged_ports = struct.unpack(">B", value[2])[0]
            untagged_ports = struct.unpack(">B", value[3])[0]
        else:
            tagged_ports = value[2]
            untagged_ports = value[3]
        out_tagged_ports = []
        out_untagged_ports = []
        for port in list(self.BIN_PORTS.keys()):
            if (tagged_ports & self.BIN_PORTS[port] > 0):
                out_tagged_ports.append(port)
            if (untagged_ports & self.BIN_PORTS[port] > 0):
                out_untagged_ports.append(port)
        rtn = {
            "vlan_id": struct.unpack(">h", value[0:2])[0],
            "tagged_ports": out_tagged_ports,
            "untagged_ports": out_untagged_ports
        }
        return rtn
        

    def pack_py(self, value):
        tagged = self.pack_port(value[1])
        untagged = self.pack_port(value[2])
        rtn = struct.pack(">hBB", int(value[0]), tagged, untagged)
        return rtn

    def unpack_cmd(self, value):
        return self.unpack_py(value)

    def get_num_args(self):
        return 3

    def get_metavar(self):
        return ("VLAN_ID", "TAGGED_PORTS", "UNTAGGED_PORTS")

    def print_result(self, value):
        print("%-30s%7s %14s %s" % (self.get_name().capitalize(), "VLAN_ID",
                                      "Tagged-Ports","Untagged-Ports"))
        if type(value) is list:
            for row in value:
                print("%-30s%7d %14s %s" % ("",
                        int(row["vlan_id"]),
                        ",".join([str(x) for x in row["tagged_ports"]]),
                        ",".join([str(x) for x in row["untagged_ports"]])))
        else:
            print("%-30s%7d %14s %s" % ("",
                        int(value["vlan_id"]),
                        ",".join([str(x) for x in value["tagged_ports"]]),
                        ",".join([str(x) for x in value["untagged_ports"]])))
          

        
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
        for row in value:
            print("%-30s%4d %7d" % ("",
                                        row["port"],
                                        row["vlan_id"]))


    def get_set_help(self):
        return "an untagged package on PORT will get this VLAN_ID"
################################################################################


class UnknownValueException(Exception):
    "Found something which I don't know"


class PslTypQos(PslTyp):
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

    def unpack_py(self, value):
        dst_port, fixme, src_ports = struct.unpack(">bbb", value)
        out_src_ports = []
        for port in list(self.BIN_PORTS.keys()):
            if (src_ports & self.BIN_PORTS[port] > 0):
                out_src_ports.append(port)

        if dst_port == 0:
            return "No Port Mirroring has been set up"
        rtn = {
            "dst_port": dst_port,
            "fixme": fixme,
            "src_ports": out_src_ports,
        }
        return rtn

    def pack_py(self, value):
        if int(value[0]) == 0:
            return struct.pack(">bbb", 0, 0, 0)
        dst_ports = 0
        for dport in value[1].split(","):
            dst_ports += self.BIN_PORTS[int(dport)]
        return struct.pack(">bbb", int(value[0]), 0, dst_ports)
        
    def unpack_cmd(self, value):
        return self.unpack_py(value)

    def is_setable(self):
        return True

    def get_num_args(self):
        return 2

    def get_metavar(self):
        return ("DST_PORTS","SRC_PORTS")

    def get_set_help(self):
        return "SET DST_PORTS and SRC_PORTS to 0 to disable"
