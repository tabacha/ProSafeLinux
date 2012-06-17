# -*- coding: utf-8 -*-
import binascii
import struct
import ipaddr


class Psl_typ:
    def __init__(self, cmd_id, name):
        self.cmd_id = cmd_id
        self.name = name

    def getId(self):
        return self.cmd_id

    def getName(self):
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
        print "%-30s%s" % (self.getName(). capitalize(), value)

    def isSetable(self):
        return True

    def isQueryAble(self):
        return True

###############################################################################


class psl_typ_string(Psl_typ):
    def __init__(self, cmd_id, name):
        self.cmd_id = cmd_id
        self.name = name

    def pack_py(self, value):
        return value

    def unpack_py(self, value):
        return value

    def pack_cmd(self, value):
        return value

    def unpack_cmd(self, value):
        return value

###############################################################################
class psl_typ_password(psl_typ_string):
    def __init__(self, cmd_id,name,setable):
        self.cmd_id = cmd_id
        self.name = name
        self.setable=setable

    def isQueryAble(self):
        return False

    def isSetable(self):
        return self.setable


################################################################################

class psl_typ_boolean(Psl_typ):
    def __init__(self, cmd_id,name):
        self.cmd_id = cmd_id
        self.name = name

    def pack_py(self,value):
        if (value):
            return struct.pack(">b",0x01)
        else:
            return struct.pack(">b",0x00)

    def unpack_py(self,value):
        return (value==0x01)

    def pack_cmd(self,value):
        return self.pack_py(value.lowercase=="on")

    def unpack_cmd(self,value):
        if (self.unpack_py(value)):
            return "on"
        else:
            return "off"


###############################################################################
class psl_typ_action(psl_typ_boolean):
    def __init__(self, cmd_id,name):
        self.cmd_id = cmd_id
        self.name = name

    def pack_py(self,value):
        return struct.pack(">b",0x01)

    def isQueryAble(self):
        return False

################################################################################

class psl_typ_mac(Psl_typ):
    def __init__(self, cmd_id,name):
        self.cmd_id = cmd_id
        self.name = name

    def pack_py(self,v):
        if (len(v)==17):
            return binascii.unhexlify(v[0:2]+v[3:5]+v[6:8]+
                                      v[9:11]+v[12:14]+v[15:17])
        if (len(v)==12):
            return binascii.unhexlify(v)
        raise "unkown mac format="+v

    def unpack_py(self,value):
        mac=binascii.hexlify(value)
        return (mac[0:2]+":"+mac[2:4]+":"+mac[4:6]+":"+mac[6:8]+
               ":"+mac[8:10]+":"+mac[10:12])

    def pack_cmd(self,value):
        return self.pack_py(self,value)

    def unpack_cmd(self,value):
        return self.unpack_py(self,value)

################################################################################

class psl_typ_ipv4(Psl_typ):
    def __init__(self, cmd_id,name):
        self.cmd_id = cmd_id
        self.name = name

    def pack_py(self,value):
        i=(int)(ipaddr.IPv4Address(value))
        r=struct.pack(">I",i)
        return r

    def unpack_py(self,value):
        a=struct.unpack(">I",value)[0]
        return "%s" % ipaddr.IPv4Address(a)

    def pack_cmd(self,value):
        return self.pack_py(self,value)

    def unpack_cmd(self,value):
        return self.unpack_py(self,value)

################################################################################

class psl_typ_hex(Psl_typ):
    def __init__(self, cmd_id,name):
        self.cmd_id = cmd_id
        self.name = name

    def pack_py(self,value):
        return binascii.unhexlify(value)

    def unpack_py(self,value):
        return binascii.hexlify(value)

    def pack_cmd(self,value):
        return self.pack_py(self,value)

    def unpack_cmd(self,value):
        return self.unpack_py(self,value)
################################################################################

class psl_typ_end(psl_typ_hex):
    def __init__(self, cmd_id,name):
        self.cmd_id = cmd_id
        self.name = name

    def isSetable(self):
        return False

    def isQueryAble(self):
        return False


################################################################################

class psl_typ_speed_stat(Psl_typ):
    SPEED_NONE=0x00
    SPEED_10MH=0x01
    SPEED_10ML=0x02
    SPEED_100MH=0x03
    SPEED_100ML=0x04
    SPEED_1G=0x05
    def __init__(self, cmd_id,name):
        self.cmd_id = cmd_id
        self.name = name
    def unpack_py(self,v):
        r={
            "port":struct.unpack(">b",v[0])[0],
            "speed":struct.unpack(">b",v[1])[0],
            "rest":binascii.hexlify(v[2:]),
        }
        return r

    def isSetable(self):
        return False
    def print_result(self,value):
        print "%-30s%4s%15s%10s" %("Speed Statistic:","Port","Speed","FIXME")
        for row in value:
            speed=row["speed"]
            if speed==psl_typ_speed_stat.SPEED_NONE:
                speed="Not conn."
            if speed==psl_typ_speed_stat.SPEED_10MH:
                speed="10 Mbit/s H"
            if speed==psl_typ_speed_stat.SPEED_10ML:
                speed="10 Mbit/s L"
            if speed==psl_typ_speed_stat.SPEED_100MH:
                speed="100 Mbit/s H"
            if speed==psl_typ_speed_stat.SPEED_100ML:
                speed="100 Mbit/s L"
            if speed==psl_typ_speed_stat.SPEED_1G:
                speed="1 Gbit/s"
            print "%-30s%4d%15s%10s" %("",row["port"],speed,row["rest"])


################################################################################

class psl_typ_port_stat(Psl_typ):
    def __init__(self, cmd_id,name):
        self.cmd_id = cmd_id
        self.name = name
    def unpack_py(self,v):
        r={
            "port":struct.unpack(">b",v[0])[0],
            "rec":struct.unpack(">Q",v[1:9])[0],
            "send":struct.unpack(">Q",v[10:18])[0],
            "rest":binascii.hexlify(v[19:]),
        }
        return r

    def isSetable(self):
        return False
    def print_result(self,value):
        print "%-30s%4s%15s%15s %s" %("Port Statistic:","Port",
                                      "Rec.","Send","FIXME")
        for row in value:
            print "%-30s%4d%15d%15d %s" %("",row["port"],row["rec"],
                                          row["send"],row["rest"])

################################################################################

class psl_typ_bandwith(Psl_typ):
    def __init__(self, cmd_id,name):
        self.cmd_id = cmd_id
        self.name = name
    def unpack_py(self,v):
        r={
            "port":struct.unpack(">b",v[0])[0],
            "limit":struct.unpack(">h",v[3::])[0],
            "rest":binascii.hexlify(v[1:2]),
        }
        return r

################################################################################

class psl_typ_vlanid(Psl_typ):
    def __init__(self, cmd_id,name):
        self.cmd_id = cmd_id
        self.name = name
    def unpack_py(self,v):
        r={
            "port":struct.unpack(">b",v[0])[0],
            "id":struct.unpack(">h",v[1:])[0],
        }
        return r