# -*- coding: utf-8 -*-
import binascii
import struct
import ipaddr


class PslTyp:
    def __init__(self, cmd_id, name):
        self.cmd_id = cmd_id
        self.name = name

    def get_id(self):
        return self.cmd_id

    def get_name(self):
        return self.name

    def pack_py(self, value):
        raise NotImplementedError

    def unpack_py(self, value):
        raise NotImplementedError

    def pack_cmd(self, value):
        raise NotImplementedError

    def unpack_cmd(self, value):
        raise NotImplementedError

    def print_result(self, value):
        print "%-30s%s" % (self.get_name(). capitalize(), value)

    def is_setable(self):
        return True

    def is_queryable(self):
        return True

###############################################################################


class PslTypString(PslTyp):

    def pack_py(self, value):
        return value

    def unpack_py(self, value):
        return value

    def pack_cmd(self, value):
        return value

    def unpack_cmd(self, value):
        return value

###############################################################################
class PslTypPassword(PslTypString):
    def __init__(self, cmd_id, name, setable):
        PslTypString.__init__(self, cmd_id, name)
        self.setable = setable

    def is_queryable(self):
        return False

    def is_setable(self):
        return self.setable


################################################################################

class PslTypBoolean(PslTyp):

    def pack_py(self, value):
        if (value):
            return struct.pack(">b", 0x01)
        else:
            return struct.pack(">b", 0x00)

    def unpack_py(self, value):
        return (value == 0x01)

    def pack_cmd(self, value):
        return self.pack_py(value.lowercase == "on")

    def unpack_cmd(self, value):
        if (self.unpack_py(value)):
            return "on"
        else:
            return "off"


###############################################################################
class PslTypAction(PslTypBoolean):

    def pack_py(self, value):
        return struct.pack(">b", 0x01)

    def is_queryable(self):
        return False

################################################################################

class PslTypMac(PslTyp):

    def pack_py(self, val):
        if (len(val) == 17):
            return binascii.unhexlify(val[0:2]+val[3:5]+val[6:8]+
                                      val[9:11]+val[12:14]+val[15:17])
        if (len(val) == 12):
            return binascii.unhexlify(val)
        raise "unkown mac format="+val

    def unpack_py(self, value):
        mac = binascii.hexlify(value)
        return (mac[0:2]+":"+mac[2:4]+":"+mac[4:6]+":"+mac[6:8]+
               ":"+mac[8:10]+":"+mac[10:12])

    def pack_cmd(self, value):
        return self.pack_py(self, value)

    def unpack_cmd(self, value):
        return self.unpack_py(self, value)

################################################################################

class PslTypIpv4(PslTyp):

    def pack_py(self, value):
        i = (int)(ipaddr.IPv4Address(value))
        return struct.pack(">I", i)

    def unpack_py(self, value):
        adr = struct.unpack(">I", value)[0]
        return "%s" % ipaddr.IPv4Address(adr)

    def pack_cmd(self, value):
        return self.pack_py(self, value)

    def unpack_cmd(self, value):
        return self.unpack_py(self, value)

################################################################################

class PslTypHex(PslTyp):

    def pack_py(self, value):
        return binascii.unhexlify(value)

    def unpack_py(self, value):
        return binascii.hexlify(value)

    def pack_cmd(self, value):
        return self.pack_py(self, value)

    def unpack_cmd(self, value):
        return self.unpack_py(self, value)

################################################################################

class PslTypHexNoQuery(PslTypHex):

    def is_queryable(self):
        return False
    
################################################################################

class PslTypEnd(PslTypHex):

    def is_setable(self):
        return False

    def is_queryable(self):
        return False

    def print_result(self, value):
        pass

################################################################################

class PslTypSpeedStat(PslTyp):
    SPEED_NONE = 0x00
    SPEED_10MH = 0x01
    SPEED_10ML = 0x02
    SPEED_100MH = 0x03
    SPEED_100ML = 0x04
    SPEED_1G = 0x05

    def unpack_py(self, value):
        rtn = {
            "port":struct.unpack(">b", value[0])[0],
            "speed":struct.unpack(">b", value[1])[0],
            "rest":binascii.hexlify(value[2:]),
        }
        return rtn

    def is_setable(self):
        return False
    
    def print_result(self, value):
        print "%-30s%4s%15s%10s" % ("Speed Statistic:", "Port", 
                                    "Speed", "FIXME")
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
            print "%-30s%4d%15s%10s" % ("", row["port"], speed, row["rest"])


################################################################################

class PslTypPortStat(PslTyp):
        
    def unpack_py(self, val):
        rtn = {
            "port":struct.unpack(">b",val[0])[0],
            "rec":struct.unpack(">Q",val[1:9])[0],
            "send":struct.unpack(">Q",val[10:18])[0],
            "rest":binascii.hexlify(val[19:]),
        }
        return rtn

    def is_setable(self):
        return False
    
    def print_result(self, value):
        print "%-30s%4s%15s%15s %s" % ("Port Statistic:", "Port",
                                      "Rec.", "Send", "FIXME")
        for row in value:
            print "%-30s%4d%15d%15d %s" % ("", row["port"], row["rec"],
                                          row["send"], row["rest"])

################################################################################

class PslTypBandwith(PslTyp):
    SPEED_LIMIT_NONE = 0x0000
    SPEED_LIMIT_512K = 0x0001
    SPEED_LIMIT_1M   = 0x0002
    SPEED_LIMIT_2M   = 0x0003
    SPEED_LIMIT_4M   = 0x0004
    SPEED_LIMIT_8M   = 0x0005
    SPEED_LIMIT_16M  = 0x0006
    SPEED_LIMIT_32M  = 0x0007
    SPEED_LIMIT_64M  = 0x0008
    SPEED_LIMIT_128M = 0x0009
    SPEED_LIMIT_256M = 0x000a
    SPEED_LIMIT_512M = 0x000b
    
    speed_to_string = {
        SPEED_LIMIT_NONE:" NONE ",
        SPEED_LIMIT_512K:"  0.5M",
        SPEED_LIMIT_1M  :"  1.0M",
        SPEED_LIMIT_2M  :"  2.0M",
        SPEED_LIMIT_4M  :"  4.0M",
        SPEED_LIMIT_8M  :"  8.0M",
        SPEED_LIMIT_16M :" 16.0M",
        SPEED_LIMIT_32M :" 32.0M",
        SPEED_LIMIT_64M :" 64.0M",
        SPEED_LIMIT_128M:"128.0M",
        SPEED_LIMIT_256M:"256.0M",
        SPEED_LIMIT_512M:"512.0m" 
        }
    
    def unpack_py(self, value):
        rtn = {
            "port":struct.unpack(">b", value[0])[0],
            "limit":struct.unpack(">h", value[3::])[0],
            "rest":binascii.hexlify(value[1:2]),
        }
        return rtn

    def print_result(self, value):
        print "%-30s%4s%15s %s" % (self.get_name().capitalize(), "Port",
                                      "Limit",  "FIXME")
        for row in value:
            print "%-30s%4d%15s %s " % ("", 
                                        row["port"], 
                                        self.speed_to_string[row["limit"]],
                                        row["rest"])


################################################################################

class PslTypVlanId(PslTyp):
    BIN_PORTS = { 1:0x80,
                  2:0x40,
                  3:0x20,
                  4:0x10,
                  5:0x08,
                  6:0x04,
                  7:0x02,
                  8:0x01
                  }
    def unpack_py(self, value):
        ports = struct.unpack(">B", value[2:])[0]
        out_ports = []
        for port in self.BIN_PORTS.keys():
            if ( ports & self.BIN_PORTS[port] >0 ):
                out_ports.append(port)
        rtn = {
            "vlan_id":struct.unpack(">h", value[0:2])[0],
            "ports":out_ports
        }
        return rtn