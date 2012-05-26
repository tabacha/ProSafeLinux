#!/usr/bin/python
import socket 
import time
import binascii
import pprint
import struct
import random

class gs105e:
	def __init__(self,host,port):
		self.myhost = host
		self.myport = port
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		self.socket.bind((host, port))
		self.seq = random.randint(100,2000)
		self.srcmac = 0x00218698da1e

	def recv(self,recvfunc,maxlen=8192,timeout=0.005):
		self.socket.settimeout(timeout)
		try:
			message, address = self.socket.recvfrom(maxlen)
		except socket.timeout:
			return None
		self.recvfunc(message,address)
		self.recv(recvfunc,maxlen,timeout)

	def parse_packet(self,p,hex=0):
		data = {}
		data["seq"]= p[22:24]
		data["cmd"]= p[32:34]
		data["mymac"]= p[8:14]
		data["theirmac"]= p[14:20]
		if hex == 1:
			for a in data: 
				data[a]=binascii.hexlify(data[a])
		return data

	def recvfunc(self,m,a):
		hexdata = self.parse_packet(m,1)
		data = self.parse_packet(m)

		if data["seq"] == "\x00\x01":
			pass
		print hexdata["theirmac"]

	def send(self,host,port,data):
		self.socket.sendto(data,(host,port))
		self.seq+=1


	def baseudp(self,cmd,ctype=0x0101,destmac=0):
		reserved = "\x00"
		data = struct.pack(">h",ctype) + 6* reserved + struct.pack('>LHLH', self.srcmac >> 16, self.srcmac & 0xffff, destmac >> 16, destmac & 0xffff) + 2*reserved  
		data += struct.pack(">h",self.seq)
		data +=  "NSDP" + 4 * reserved + cmd 
		return data

	def discover(self):
		reserved = "\x00"
		cmd = "\x00\x01"

		data = self.baseudp(cmd)
		data += 3 * "\x00" + "\x02" 
		data += 3 * "\x00" + "\x03" +  3 * "\x00" + "\x04" + 3* "\x00" + "\x05"
		data += 3 * "\x00" + "\x06" +  3 * "\x00" + "\x07" + 3* "\x00" + "\x08"
		data += 3 * "\x00" + "\x0b" +  3 * "\x00" + "\x0c" + 3* "\x00" + "\x0d"
		data += 3 * "\x00" + "\x0e" +  3 * "\x00" + "\x0f" + 2 * "\x00"
		data +=  "\x74" + 3 * "\x00" 
		data += 2* "\xff" + 2* "\x00"
#		self.send("255.255.255.255",63322, data)
#		time.sleep(1)
		self.send("255.255.255.255",63322, data)
		time.sleep(0.7)

		data = self.baseudp(cmd)
		data += 3 * "\x00" + "\x02" 
		data += 3 * "\x00" + "\x03" +  3 * "\x00" + "\x04" + 3* "\x00" + "\x05"
		data += 3 * "\x00" + "\x06" +  3 * "\x00" + "\x07" + 3* "\x00" + "\x08"
		data += 3 * "\x00" + "\x0b" +  3 * "\x00" + "\x0c" + 3* "\x00" + "\x0d"
		data += 3 * "\x00" + "\x0e" +  3 * "\x00" + "\x0f" + 2 * "\x00"
		data += 2* "\xff" + 2* "\x00"
	#	self.send("255.255.255.255",63322, data)
		self.recv(None)

	def passwd(self, dest, oldpass, newpass):
		reserved = "\x00"
		cmd = "\x00\x0a"

		data = self.baseudp(cmd, destmac=dest, ctype=0x0103)
		data += struct.pack(">h", len(oldpass))
		data += oldpass
		data += struct.pack(">h", 9)
		data += struct.pack(">h", len(newpass))
		data += newpass
		data += 2* "\xff" + 2* "\x00"
		self.send("255.255.255.255",63322, data)
		time.sleep(0.2)
		self.recv(None)

g = gs105e('',63321)
#g.discover()
g.passwd(0xe091f5936b94, 'kat', 'hemmeligt')
