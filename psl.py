#!/usr/bin/python
# -*- coding: utf-8 -*-
import psl 
import time
import binascii
import pprint
import struct
import random
import sys
import socket
import ipaddr
import fcntl
import IN
import psl_typ
import inspect

def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl( s.fileno(), 0x8915, # SIOCGIFADDR
                                         struct.pack('256s', ifname[:15]))[20:24])

def pack_mac(v):
    if (len(v)==17):
        return binascii.unhexlify(v[0:2]+v[3:5]+v[6:8]+v[9:11]+v[12:14]+v[15:17])
    if (len(v)==12):
        return binascii.unhexlify(v)
    raise "unkown mac format="+v

def unpack_mac(value):
    mac=binascii.hexlify(value)
    return mac[0:2]+":"+mac[2:4]+":"+mac[4:6]+":"+mac[6:8]+":"+mac[8:10]+":"+mac[10:12]

class psl:
    CMD_MODEL    = psl_typ.psl_typ_string(0x0001,"model")
    CMD_FIMXE2   = psl_typ.psl_typ_hex(0x0002,"fixme2")
    CMD_NAME     = psl_typ.psl_typ_string(0x0003,"name")
    CMD_MAC      = psl_typ.psl_typ_mac(0x0004,"MAC")
    CMD_FIMXE5   = psl_typ.psl_typ_hex(0x0005,"fixme5")
    CMD_IP       = psl_typ.psl_typ_ipv4(0x0006,"ip")
    CMD_NETMASK  = psl_typ.psl_typ_ipv4(0x0007,"netmask")
    CMD_GATEWAY  = psl_typ.psl_typ_ipv4(0x0008,"gateway")
    CMD_NEW_PASSWORD = psl_typ.psl_typ_password(0x0009,"new_password",True)
    CMD_PASSWORD = psl_typ.psl_typ_password(0x000a,"password",False)
    CMD_DHCP     = psl_typ.psl_typ_boolean(0x000b,"dhcp")
    CMD_FIXMEC   = psl_typ.psl_typ_hex(0x000c,"fixmeC")
    CMD_FIRMWAREV= psl_typ.psl_typ_string(0x000d,"firmwarever")
    CMD_FIMXEE   = psl_typ.psl_typ_hex(0x000e,"fixmeE")
    CMD_FIXMEF   = psl_typ.psl_typ_hex(0x000f,"fixmeF")
    CMD_REBOOT   = psl_typ.psl_typ_action(0x0013,"reboot")
    CMD_FACTORY_RESET = psl_typ.psl_typ_action(0x0400,"factory_reset")
    CMD_SPEED_STAT= psl_typ.psl_typ_speed_stat(0x0c00,"speed-stat")
    CMD_PORT_STAT= psl_typ.psl_typ_port_stat(0x1000,"port-stat")
    CMD_RESET_PORT_STAT=psl_typ.psl_typ_action(0x1400,"reset-port-stat")
    CMD_TEST_CABLE=psl_typ.psl_typ_action(0x1800,"test-cable")
    CMD_TEST_CABLE_RESP=psl_typ.psl_typ_hex(0x1c00,"test-cable-resp")
    CMD_VLAN_SUPP=psl_typ.psl_typ_hex(0x2000,"vlan-supp")
    CMD_VLAN_ID  = psl_typ.psl_typ_vlanid(0x2400,"vlan-id")
    CMD_VLAN802_ID = psl_typ.psl_typ_hex(0x2800,"vlan802-id")
    CMD_VLANPVID = psl_typ.psl_typ_hex(0x3000,"vlan-pvid")
    CMD_QUALITY_OF_SERVICE= psl_typ.psl_typ_hex(0x3400,"qos")
    CMD_PORT_BASED_QOS= psl_typ.psl_typ_hex(0x3800,"port-bases-qos")
    CMD_BANDWITH_INCOMMING_LIMIT= psl_typ.psl_typ_bandwith(0x4c00,"bandwith-in")
    CMD_BANDWITH_OUTGOING_LIMIT= psl_typ.psl_typ_bandwith(0x5000,"bandwith-out")
    CMD_FIXME5400= psl_typ.psl_typ_hex(0x5400,"fxime5400")
    CMD_BROADCAST_FILTER= psl_typ.psl_typ_hex(0x5800,"broadcast-filter")
    CMD_PORT_MIRROR= psl_typ.psl_typ_hex(0x5c00,"port-mirror")
    CMD_NUMBER_OF_PORTS= psl_typ.psl_typ_hex(0x6000,"number-of-ports") 
    CMD_FIXME6800= psl_typ.psl_typ_hex(0x6800,"fixme6800")
    CMD_BLOCK_UNKOWN_MULTICAST= psl_typ.psl_typ_hex(0x6c00,"block-unknown-multicast")
    CMD_IGMP_SPOOFING= psl_typ.psl_typ_boolean(0x7000,"igmp-spoofing")
    CMD_FIXME7400= psl_typ.psl_typ_hex(0x7400,"fixme7400")
    CMD_END	     = psl_typ.psl_typ_end(0xffff,"END")

    CTYPE_QUERY_REQUEST= 0x0101
    CTYPE_QUERY_RESPONSE= 0x0102
    CTYPE_TRANSMIT_REQUEST = 0x103
    CTYPE_TRANSMIT_RESPONSE = 0x104

    SPEED_LIMIT_NONE=0x0000
    SPEED_LIMIT_512K=0x0001
    SPEED_LIMIT_1M  =0x0002
    SPEED_LIMIT_2M  =0x0003
    SPEED_LIMIT_4M  =0x0004
    SPEED_LIMIT_8M  =0x0005
    SPEED_LIMIT_16M =0x0006
    SPEED_LIMIT_32M =0x0007
    SPEED_LIMIT_64M =0x0008
    SPEED_LIMIT_128M=0x0009
    SPEED_LIMIT_256M=0x000a
    SPEED_LIMIT_512M=0x000b

    BIN_PORT1=0x80
    BIN_PORT2=0x40
    BIN_PORT3=0x20
    BIN_PORT4=0x10
    BIN_PORT5=0x08
    BIN_PORT6=0x04
    BIN_PORT7=0x02
    BIN_PORT8=0x01

    FLAG_PASSWORD_ERROR=0x000a        

    RECPORT=63321
    SENDPORT=63322

    def __init__(self):
        self.myhost = None
        self.srcmac = None
        self.ssocket = None
        self.rsocket = None

        self.seq = random.randint(100,2000)
        self.outdata={}
        self.debug = False
        self.mac_cache={}
        self.cmd_by_id={}
        self.cmd_by_name={}
        for key,value in  inspect.getmembers(psl):
            if key.startswith("CMD_"):
                self.cmd_by_name[value.getName()]=value
                self.cmd_by_id[value.getId()]=value

    def bind(self,interface):
        self.myhost = get_ip_address(interface)
        self.srcmac = pack_mac(getHwAddr(interface))

            # send socket
        self.ssocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) 

        # The following requires root permission so we do not do this:
        # self.socket.setsockopt(socket.SOL_SOCKET,IN.SO_BINDTODEVICE,"eth1"+'\0')	

        self.ssocket.bind((self.myhost, self.RECPORT))

        # recive socket
        self.rsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.rsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) 
        self.rsocket.bind(("255.255.255.255",self.RECPORT))

    def getQueryCmds(self):
        rtn=[]
        for cmd in self.cmd_by_name.values():
            if cmd.isQueryAble():
                rtn.append(cmd)
        return rtn

    def getCmdByName(self,name):
        return self.cmd_by_name[name]

    def setDebugOutput(self):
        self.debug = True


    def recv(self,recvfunc,maxlen=8192,timeout=0.005):
        self.rsocket.settimeout(timeout)
        try:
            message, address = self.rsocket.recvfrom(maxlen)
        except socket.timeout:
            return None
        if self.debug:
            print "recv="+binascii.hexlify(message)
        if recvfunc is not None:	
            recvfunc(message,address)
        self.recv(recvfunc,maxlen,timeout)

    def parse_packet(self,p,unknown_warn):
        data = {}
        data["seq"]= struct.unpack(">H",p[22:24])[0]
        data["ctype"]= struct.unpack(">H",p[0:2])[0]
        data["flags"]= struct.unpack(">H",p[4:6])[0]
        data["mymac"]= binascii.hexlify(p[8:14])
        data["theirmac"]= binascii.hexlify(p[14:20])
        pos=32
        cmd_id=0
        while(cmd_id!=self.CMD_END.getId()):
            cmd_id= struct.unpack(">H",p[pos:(pos+2)])[0]
            if cmd_id in self.cmd_by_id:
                cmd=self.cmd_by_id[cmd_id]
            else:
                if unknown_warn:
                    print "Unkown Response %d" % cmd_id
                cmd=psl_typ.psl_typ_hex(cmd_id,"UNKOWN %d" %cmd_id)
            pos=pos+2
            len=struct.unpack(">H",p[pos:(pos+2)])[0]
            pos=pos+2
            if len>0:
                value = cmd.unpack_py(p[pos:(pos+len)])
            else:
                value=None
            if cmd in data:
                if type(data[cmd])!=type(list()):
                    data[cmd]=[data[cmd]]
                data[cmd].append(value)
            else:
                data[cmd]=value
            if self.debug:   
                print "cmd=",cmd_id," len=",len," data=",binascii.hexlify(p[pos:(pos+len)])
            pos=pos+len
        #pprint.pprint(data)
        return data

    def discoverfunc(self,m,a):
        #print "==FOUND SWITCH=="
        data = self.parse_packet(m,True)
        dhcpstr=""
        if (data[self.CMD_DHCP]):
            dhcpstr=" DHCP=on"
        print " * %s\t%s\t%s\t%s\t%s" % (data[self.CMD_MAC],data[self.CMD_IP],data[self.CMD_MODEL],data[self.CMD_NAME],dhcpstr)

    def storediscoverfunc(self,m,a):
        #print "==FOUND SWITCH=="
        data = self.parse_packet(m,True)
        if self.debug:
            print "Store MAC,IP: "+data[self.CMD_MAC]+" "+data[self.CMD_IP]
        self.mac_cache[data[self.CMD_MAC]]=data[self.CMD_IP]
        #print " * %s\t%s\t%s\t%s\t%s" % (data[self.CMD_MAC],data[self.CMD_IP],data[self.CMD_MODEL],data[self.CMD_NAME],dhcpstr)

    def transfunc(self,m,a):
        #print "==FOUND SWITCH=="
        data = self.parse_packet(m,True)
        if self.debug:
            pprint.pprint(data)
            if data["flags"]==self.FLAG_PASSWORD_ERROR:
                print "wrong password"
            if data["flags"]==0:
                print "success"

    def storefunc(self,m,a):
        #print "==FOUND SWITCH=="
        self.outdata = self.parse_packet(m,True)
        if self.debug:
            pprint.pprint(self.outdata)

            if self.outdata["flags"]==self.FLAG_PASSWORD_ERROR:
                print "Flags: wrong password"

            if self.outdata["flags"]==0:
                print "Flags: success"

    def rec_raw(self,m,a):
        try:
            self.outdata = self.parse_packet(m,False)
        except:
            pass
        self.outdata["raw"]=binascii.hexlify(m)

    def send(self,host,port,data):
        if self.debug:
            print "send to ip "+host+" data="+binascii.hexlify(data)
        self.ssocket.sendto(data,(host,port))
        self.seq+=1

    def baseudp(self,ctype,destmac):
        reserved = "\x00"
        if destmac is None:
            destmac=6*"\x00"
        if len(destmac)>6:
            destmac=pack_mac(destmac)
        data = struct.pack(">h",ctype) + 6* reserved + self.srcmac +destmac + 2*reserved  
        data += struct.pack(">h",self.seq)
        data +=  "NSDP" + 4 * reserved 
        return data

    def addudp(self,cmd,datain=None):
        data = struct.pack(">H",cmd.getId())
        if (datain is None):
            data += struct.pack(">H", 0)
        else:
            pdata=cmd.pack_py(datain)
            data += struct.pack(">H", len(pdata))
            data += pdata
        return data

    def ip_from_mac(self,mac):
        if mac is None:
            return "255.255.255.255"
        if mac in self.mac_cache:
            return self.mac_cache[mac]
        #print "mac="+mac
        # FIXME: Search in /proc/net/arp if mac there use this one
        #with open("/proc/net/arp") as f:
        # for line in f:
        #   print line
        query_arr=[ self.CMD_MAC, self.CMD_IP];
        self.query(query_arr,mac,self.storediscoverfunc,useIpFunc=False)
        if mac in self.mac_cache:
            return self.mac_cache[mac]
        print "cant find mac: "+mac
        return "255.255.255.255"   

    def query(self,cmd_arr,mac,func,useIpFunc=True):
        if useIpFunc:
            ip=self.ip_from_mac(mac)
        else:
            ip="255.255.255.255"
        data = self.baseudp(destmac=mac,ctype=self.CTYPE_QUERY_REQUEST)
        for cmd in cmd_arr:
            data+=self.addudp(cmd);
        data+=self.addudp(self.CMD_END)
        self.outdata={}
        self.send(ip,self.SENDPORT, data)
        time.sleep(0.7)
        self.recv(func)


    def transmit(self,cmd_arr,mac,func):
        ip=self.ip_from_mac(mac)
        data = self.baseudp(destmac=mac,ctype=self.CTYPE_TRANSMIT_REQUEST)
        if self.CMD_PASSWORD in cmd_arr:
            data+=self.addudp(self.CMD_PASSWORD,cmd_arr[self.CMD_PASSWORD])
        for cmd,pdata in cmd_arr.items():
            if cmd!=self.CMD_PASSWORD:
                data+=self.addudp(cmd,pdata);
        data+=self.addudp(self.CMD_END)
        self.send(ip,self.SENDPORT, data)
        time.sleep(0.7)
        self.recv(func)

    def passwd(self,mac,old,new,func):
        # The Order of the CMD_PASSWORD and CMD_NEW_PASSWORD is important
        ip=self.ip_from_mac(mac)
        data = self.baseudp(destmac=mac,ctype=self.CTYPE_TRANSMIT_REQUEST)
        data+=self.addudp(self.CMD_PASSWORD,old);
        data+=self.addudp(self.CMD_NEW_PASSWORD,new);
        data+=self.addudp(self.CMD_END)
        self.send(ip,self.SENDPORT, data)
        time.sleep(0.7)
        self.recv(func)


    def discover(self):
        query_arr=[self.CMD_MODEL,
                   self.CMD_NAME,
                   self.CMD_MAC,
                   self.CMD_DHCP,
                   self.CMD_IP];
        self.query(query_arr,None,self.discoverfunc)

