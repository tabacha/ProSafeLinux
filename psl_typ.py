# -*- coding: utf-8 -*-
import binascii
import struct
import ipaddr
class psl_typ:
      def __init__(self, id,name):
	  self.id = id
	  self.name = name
		
      def getId(self):
		return self.id
		
      def getName(self):
	  return self.name

      def pack_py(self,value):
	  raise NotImplementedError
	  
      def unpack_py(self,value):
	  raise NotImplementedError
	  
      def pack_cmd(self,value):
	  raise NotImplementedError

      def unpack_cmd(self,value):
	  raise NotImplementedError
  
      def isSetable(self):
	  return True
     
      def isQueryAble(self):
	  return True
	 
###########################################################################################
class psl_typ_string(psl_typ):
      def __init__(self, id,name):
	  self.id = id
	  self.name = name
	  
      def pack_py(self,value):
	  return value
	  
      def unpack_py(self,value):
	  return value
	  
      def pack_cmd(self,value):
	  return value

      def unpack_cmd(self,value):
	  return value

###########################################################################################

class psl_typ_boolean(psl_typ):
      def __init__(self, id,name):
	  self.id = id
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
###########################################################################################

class psl_typ_mac(psl_typ):
        def __init__(self, id,name):
	  self.id = id
	  self.name = name
	  
        def pack_py(self,v):
          if (len(v)==17):
           return binascii.unhexlify(v[0:2]+v[3:5]+v[6:8]+v[9:11]+v[12:14]+v[15:17])
          if (len(v)==12):
           return binascii.unhexlify(v)
          raise "unkown mac format="+v

        def unpack_py(self,value):
	   mac=binascii.hexlify(value)
           return mac[0:2]+":"+mac[2:4]+":"+mac[4:6]+":"+mac[6:8]+":"+mac[8:10]+":"+mac[10:12]

        def pack_cmd(self,value):
	  return self.pack_py(self,value)

        def unpack_cmd(self,value):
	  return self.unpack_py(self,value)

###########################################################################################

class psl_typ_ipv4(psl_typ):
        def __init__(self, id,name):
	  self.id = id
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

###########################################################################################

class psl_typ_hex(psl_typ):
        def __init__(self, id,name):
	  self.id = id
	  self.name = name
	  
        def pack_py(self,value):
          return binascii.unhexlify(value)
          
        def unpack_py(self,value):
          return binascii.hexlify(value)

        def pack_cmd(self,value):
	  return self.pack_py(self,value)

        def unpack_cmd(self,value):
	  return self.unpack_py(self,value)

###########################################################################################

class psl_typ_speed_stat(psl_typ):
        def __init__(self, id,name):
	  self.id = id
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


###########################################################################################

class psl_typ_port_stat(psl_typ):
        def __init__(self, id,name):
	  self.id = id
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


###########################################################################################

class psl_typ_bandwith(psl_typ):
        def __init__(self, id,name):
	  self.id = id
	  self.name = name
	def unpack_py(self,v):
            r={
             "port":struct.unpack(">b",v[0])[0],
             "limit":struct.unpack(">h",v[3::])[0],
             "rest":binascii.hexlify(v[1:2]),
             }
            return r

###########################################################################################

class psl_typ_vlanid(psl_typ):
        def __init__(self, id,name):
	  self.id = id
	  self.name = name
        def unpack_py(self,v):
          r={
            "port":struct.unpack(">b",v[0])[0],
            "id":struct.unpack(">h",v[1:])[0],
           }      
          return r
