-- create nsdp protocol and its fields
p_nsdp = Proto ("nsdp","Netgear Switch Description Protocol")
-- local f_source = ProtoField.uint16("nsdp.src", "Source", base.HEX)
local f_type = ProtoField.uint16("nsdp.type", "Type", base.HEX,{
 [0x101]="Data Request",
 [0x102]="Data Response",
 [0x103]="Change Request",
 [0x104]="Change Response"
})
local f_source = ProtoField.ether("nsdp.src", "Source", base.HEX)
local f_destination = ProtoField.ether("nsdp.dst", "Destination", base.HEX)
local f_seq = ProtoField.uint16("nsdp.seq", "Seq", base.HEX)
local f_len = ProtoField.uint16("nsdp.len", "Length", base.HEX)
local f_data = ProtoField.string("nsdp.data", "Data", FT_STRING)
local f_vlan_engine = ProtoField.uint8("nsdp.vlan_engine","VLAN Engine",base.HEX,{ [0x00]="None",
 [0x01]="VLAN_Port_Based",
 [0x02]="VLAN_ID_Based",
 [0x03]="802.1Q_Port_Based",
 [0x04]="802.1Q_Extended",
})


local f_cmd = ProtoField.uint16("nsdp.cmd", "Command", base.HEX,{
	[0x0001] = "Model",
	[0x0002] = "FIXME 0x0002 (2 Bytes)",
	[0x0003] = "Name",
	[0x0004] = "MAC",
	[0x0005] = "Location",
	[0x0006] = "IP-Address",
	[0x0007] = "Netmask",
	[0x0008] = "Gateway",
	[0x0009] = "New Password",
	[0x000a] = "Password",
	[0x000b] = "DHCP Status",
	[0x000c] = "FIXME 0x000c (1 Byte)",
	[0x000d] = "Firmware Version",
	[0x000e] = "Firmware 2 Version",
	[0x000f] = "Active Firmware",
	[0x0013] = "Reboot",
	[0x0400] = "Factory Reset",
	[0x1000] = "Port Traffic Statistic",
	[0x1400] = "Reset Port Traffic Statistic",
	[0x1800] = "Test Cable",
	[0x2000] = "VLAN Engine",
	[0x2400] = "VLAN-ID",
	[0x2800] = "802VLAN-ID",
    [0x3000] = "vlan_pvid",
	[0x3400] = "QOS",
	[0x3800] = "Portbased QOS",
	[0x4c00] = "Bandwidth Limit IN",
	[0x5000] = "Bandwidth Limit OUT",
	[0x5400] = "FIXME 0x5400 (1 Byte)",
	[0x5800] = "Broadcast Bandwidth",
	[0x5c00] = "Port Mirror",
    [0x6000] = "Number of available Ports",
	[0x6800] = "IGMP Snooping Status",
	[0x6c00] = "Block Unknown Multicasts",
	[0x7000] = "IGMP Header Validation",
	[0x7400] = "FIMXE 0x7400 (8 Bytes)",
	[0x0c00] = "Speed/Link Status",
	[0xffff] = "End Request"
})
local f_password = ProtoField.string("nsdp.password", "Password", FT_STRING)
local f_newpassword = ProtoField.string("nsdp.newpassword", "New password", FT_STRING)
local f_flags = ProtoField.uint16("nsdp.flags", "Flags", base.HEX, {
	[0x000a] = "Password error"
})
local f_model =ProtoField.string("nsdp.model","Model", FT_STRING)
local f_name =ProtoField.string("nsdp.name","Name", FT_STRING)
local f_macinfo = ProtoField.ether("nsdp.macinfo", "MAC info", base.HEX)
local f_location = ProtoField.string("nsdp.location", "Location", FT_STRING)
local f_ipaddr = ProtoField.ipv4("nsdp.ipaddr","IP Address")
local f_dhcp_enable =ProtoField.uint8("nsdp.dhcp_enable","DHCP Enable")
local f_netmask = ProtoField.ipv4("nsdp.netmask","Netmask")
local f_gateway = ProtoField.ipv4("nsdp.gateway","Gateway")
local f_firmwarever_len = ProtoField.uint16("nsdp.firmwarever_len", "Firmware version LEN",base.HEX)
local f_firmwarever = ProtoField.string("nsdp.firmwarever", "Firmware version",FT_STRING)
local f_firmware2ver = ProtoField.string("nsdp.firmware2ver", "Firmware 2 version",FT_STRING)
local f_firmwareactive = ProtoField.uint8("nsdp.firmwareactive","Active firmware")
local speed_flags={
  [0x00]="None",
  [0x01]="10M",
  [0x03]="100M",
  [0x05]="1000M"
}
local f_speed = ProtoField.uint8("nsdp.speed","Speed",base.HEX, speed_flags)
local f_link = ProtoField.uint8("nsdp.link","Link",base.HEX)
local f_port=ProtoField.uint8("nsdp.port","Port Number")
local f_rec=ProtoField.uint64("nsdp.recived","Bytes received")
local f_send=ProtoField.uint64("nsdp.send","Bytes send")
local f_pkt=ProtoField.uint64("nsdp.pkt","Total packets")
local f_bpkt=ProtoField.uint64("nsdp.pkt_bcst","Broadcast packets")
local f_mpkt=ProtoField.uint64("nsdp.pkt_mcst","Multicast packets")
local f_crce=ProtoField.uint64("nsdp.crc_error","CRC errors")

--local f_debug = ProtoField.uint8("nsdp.debug", "Debug")
p_nsdp.fields = {f_type,f_source,f_destination,f_seq,f_cmd,f_password,f_newpassword,f_flags,
                 f_model,f_name,f_macinfo,f_dhcp_enable,f_port,f_rec,f_send,
                 f_pkt,f_bpkt,f_mpkt,f_crce,f_link,f_vlan_engine,f_ipaddr,
                 f_netmask,f_gateway,f_firmwarever_len,f_firmwarever,f_len,
                 f_firmware2ver, f_firmwareactive,
                 f_speed,f_location}

-- nsdp dissector function
function p_nsdp.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = p_nsdp.name

  -- create subtree for nsdp
  subtree = root:add(p_nsdp, buf(0))
  local offset = 0
  local ptype = buf(offset,2):uint()
  if ptype == 0x0104 then
     if buf:len() == offset then
        subtree:append_text(", password changed")
      else
        subtree:append_text(", logged in")
      end
  end
  subtree:add(f_type, buf(offset,2))
  offset = offset + 4
  subtree:add(f_flags, buf(offset,2))
  offset = offset + 4
  subtree:add(f_source, buf(offset,6))
  offset = offset + 6
  subtree:add(f_destination, buf(offset,6))
  offset = offset + 8
  subtree:add(f_seq, buf(offset,2))
  offset = offset + 10
  while offset < buf:len() do
    local cmd = buf(offset, 2):uint()
    local len=buf(offset+2,2):uint()
    local tree=0
    offset = offset + 4
    if cmd == 0x0001 then
	tree=subtree:add(f_model,buf(offset,len))
    elseif cmd == 0x0003 then
        tree=subtree:add(f_name,buf(offset,len))
    elseif cmd == 0x0004 and len==6 then
	tree=subtree:add(f_macinfo,buf(offset,len))
    elseif cmd == 0x0004 then
        tree=subtree:add(buf(offset,len),"MAC")
    elseif cmd == 0x0005 then
        tree=subtree:add(f_location,buf(offset,len))
    elseif cmd == 0x0006 and len==4 then
	tree=subtree:add(f_ipaddr,buf(offset,len))
    elseif cmd == 0x0006 then
        tree=subtree:add(buf(offset,len),"IP-Address")
    elseif cmd == 0x0007 and len==4 then
	tree=subtree:add(f_netmask,buf(offset,len))
    elseif cmd == 0x0007 then
        tree=subtree:add(buf(offset,len),"Netmask")
    elseif cmd == 0x0008 and len==4 then
	tree=subtree:add(f_gateway,buf(offset,len))
    elseif cmd == 0x0008 then
        tree=subtree:add(buf(offset,len),"Gateway")
    elseif cmd == 0x0009 then
        tree=subtree:add(f_newpassword, buf(offset,len))
    elseif cmd == 0x000a then
        tree=subtree:add(f_password, buf(offset,len))
    elseif cmd == 0x000b and len==1 then
        tree=subtree:add(f_dhcp_enable, buf(offset,len))
	-- 00 DHCP disabled
        -- 01 DHCP enabled
        -- CMD: 02 DHCP do a new query
    elseif cmd == 0x000b  then
        tree=subtree:add(buf(offset,len),"Query DHCP")
    elseif cmd == 0x000d then
	tree=subtree:add(f_firmwarever,buf(offset,len))
    elseif cmd == 0x000e then
        tree=subtree:add(f_firmware2ver,buf(offset,len))
    elseif cmd == 0x000f then
        if len == 1 then
            tree=subtree:add(f_firmwareactive,buf(offset,len))
        else
            tree=subtree:add(buf(offset,len),"Active Firmware?")
        end
    elseif cmd==0x0c00 and len==3 then
	   tree=subtree:add(buf(offset,1),"Speed Statistic")
	   tree:add(f_port,buf(offset,1))
	   tree:add(f_speed,buf(offset+1,1))
	   tree:add(f_link,buf(offset+2,1))
    elseif cmd==0x1000 and len==0x31 then
	   tree=subtree:add(buf(offset,1),"Port Statistic")
	   tree:add(f_port,buf(offset,1))
	   tree:add(f_rec,buf(offset+1,8))
	   tree:add(f_send,buf(offset+1+8,8))
	   tree:add(f_pkt,buf(offset+1+2*8,8))
	   tree:add(f_bpkt,buf(offset+1+3*8,8))
	   tree:add(f_mpkt,buf(offset+1+4*8,8))
	   tree:add(f_crce,buf(offset+1+5*8,8))
    elseif cmd==0x1400 and len==0x01 then
	   tree=subtree:add(buf(offset,1),"Reset Port Statistic")
	   -- 1 Byte: 0x01
    elseif cmd==0x1800 and len==0x02 then
      tree=subtree:add(buf(offset,len),"Test Cable")
	-- 1 Byte  Port 01=Port 1...08=Port 8
	-- 1 Byte alway 0x01
    elseif cmd==0x1c00 and len==0x01 then
	-- 1 Byte Port

    elseif cmd==0x1c00 and len==0x09 then
	-- 1 Byte Port
        -- 00 00 01 00 00 00 00 == No Cable
        -- 00 00 00 00 00 00 01 == OK
        -- 00 00 00 00 00 00 04 == OK
    elseif cmd==0x2000 and len==0x01 then
	   tree=subtree:add(f_vlan_engine,buf(offset,len))
    elseif cmd==0x2800 and len==0x04 then
      tree=subtree:add(buf(offset,len),"FIXME")
      -- 2 Bytes: VLAN ID (0x0ffe is all Ports
      -- 1 Byte Port Hex 01=Port 8 02=Port 7 04=Port 6 08=Port 5 10=Port Port 4 20=Port 3 40=Port 2 80=Port 1
      -- 1 Byte  Tagged Ports
    elseif cmd==0x3000 and len==0x03 then
      tree=subtree:add(buf(offset,len),"FIXME")
      -- 1 Byte Port (not binary Port8=8; Port1=1)
      -- 2 Bytes VLAN ID Port PVID
    elseif cmd==0x3400 and len==0x01 then
      tree=subtree:add(buf(offset,len),"Port Based Quality of Service")
      -- 1 Byte 0x01== port based
      -- 1 Byte 0x02== 802.1p based
    elseif cmd==0x3800 and len==0x01 then
      tree=subtree:add(buf(offset,len),"Port Based Quality of Service")
      -- 1 Byte port 
      -- 1 Byte:
      -- 0x01 == High Priority
      -- 0x02 == Middle Priority
      -- 0x03 == Normal Priority
      -- 0x04 == Low Priority
    elseif cmd==0x4c00 and len==0x05 then
      tree=subtree:add(buf(offset,len),"FIXME")
      -- 1 Byte Port (not binary Port8=8; Port1=1)
      -- 2 Bytes Unknown
      -- 2 Bytes Incomming Rate 
      --   0x0000 No Limit
      --   0x0001 512 Kbits/s
      --   0x0002 1 Mbits/s
      --   0x0003 2 Mbits/s
      --   0x0004 4 Mbits/s
      --   0x0005 8 Mbits/s
      --   0x0006 16 Mbits/s
      --   0x0007 32 Mbits/s
      --   0x0008 64 Mbits/s
      --   0x0009 128 Mbits/s
      --   0x000a 256 Mbits/s
      --   0x000b 512 Mbits/s
    elseif cmd==0x5000 and len==0x05 then
      tree=subtree:add(buf(offset,len),"FIXME")
      -- 1 Byte Port (not binary Port8=8; Port1=1)
      -- 2 Bytes Unknown
      -- 2 Bytes Outgoing Rate 
      --   0x0000 No Limit
      --   0x0001 512 Kbits/s
      --   0x0002 1 Mbits/s
      --   0x0003 2 Mbits/s
      --   0x0004 4 Mbits/s
      --   0x0005 8 Mbits/s
      --   0x0006 16 Mbits/s
      --   0x0007 32 Mbits/s
      --   0x0008 64 Mbits/s
      --   0x0009 128 Mbits/s
      --   0x000a 256 Mbits/s
      --   0x000b 512 Mbits/s
    elseif cmd==0x5c00 and len==0x03 then
      tree=subtree:add(buf(offset,len),"Port Mirroring")
      -- 00 00 00 = Disabled
      -- 1 Byte destination port
      -- 1 Byte 00
      -- 1 Byte source ports (binary port shema)
    elseif cmd==0x5800 and len==0x05 then
      tree=subtree:add(buf(offset,len),"Broadcast Filter")
      -- 1 Byte Port (not binary Port8=8; Port1=1)
      -- 2 Bytes Unknown
      -- 2 Bytes Broadcast Rate 
      --   0x0000 No Limit
      --   0x0001 512 Kbits/s
      --   0x0002 1 Mbits/s
      --   0x0003 2 Mbits/s
      --   0x0004 4 Mbits/s
      --   0x0005 8 Mbits/s
      --   0x0006 16 Mbits/s
      --   0x0007 32 Mbits/s
      --   0x0008 64 Mbits/s
      --   0x0009 128 Mbits/s
      --   0x000a 256 Mbits/s
      --   0x000b 512 Mbits/s
    elseif cmd==0x6000 and len==0x01 then
      tree=subtree:add(buf(offset,len),"Number of Ports???")
      -- 1 Byte Port (not binary Port8=8; Port1=1)
    elseif cmd==0x6c00 and len==0x01 then
      tree=subtree:add(buf(offset,len),"Block unknown MultiCast Address")
      -- 1 Byte Port (not binary Port8=8; Port1=1)
    elseif cmd==0x7000 and len==0x04 then
      tree=subtree:add(buf(offset,len),"IGMP Spoofing")
      -- 00 00 00 00 Disabled
      -- 00 01 Enabled
      -- 2 Bytes VLAN ID
    elseif cmd==0x7000 and len==0x01 then
      tree=subtree:add(buf(offset,len),"Valid IGMP Spoofing")
      -- 01 enabled
      -- 00 disabled
    else
      tree=subtree:add(buf(offset,len),"FIXME")
    end
    tree:add(f_cmd,buf(offset-4,2))
    tree:add(f_len,buf(offset-2,2))
    tree:add(buf(offset,len),"DATA")
    offset=offset+len
  end
end

function p_nsdp.init()
  -- init
end

local tcp_dissector_table = DissectorTable.get("udp.port")
dissector = tcp_dissector_table:get_dissector(63321)
tcp_dissector_table:add(63321, p_nsdp)

local tcp_dissector_table = DissectorTable.get("udp.port")
dissector = tcp_dissector_table:get_dissector(63322)
tcp_dissector_table:add(63322, p_nsdp)
