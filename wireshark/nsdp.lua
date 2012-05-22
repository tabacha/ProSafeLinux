-- create nsdp protocol and its fields
p_nsdp = Proto ("nsdp","Netgear Switch Description Protocol")
-- local f_source = ProtoField.uint16("nsdp.src", "Source", base.HEX)
local f_type = ProtoField.uint16("nsdp.type", "Type", base.HEX)
local f_source = ProtoField.ether("nsdp.src", "Source", base.HEX)
local f_destination = ProtoField.ether("nsdp.dst", "Destination", base.HEX)
local f_seq = ProtoField.uint16("nsdp.seq", "Seq", base.HEX)
local f_len = ProtoField.uint16("nsdp.len", "Length", base.HEX)
local f_data = ProtoField.string("nsdp.data", "Data", FT_STRING)
local f_cmd = ProtoField.uint16("nsdp.cmd", "Command", base.HEX)
local f_password = ProtoField.string("nsdp.password", "Password", FT_STRING)
local f_newpassword = ProtoField.string("nsdp.newpassword", "New password", FT_STRING)
local f_flags = ProtoField.uint16("nsdp.flags", "Flags", base.HEX, {
	[0x000a] = "Password error"
})
local f_model =ProtoField.string("nsdp.model","Model", FT_STRING)
local f_name =ProtoField.string("nsdp.name","Name", FT_STRING)
local f_macinfo = ProtoField.ether("nsdp.macinfo", "MAC info", base.HEX)
local f_ipaddr = ProtoField.ipv4("nsdp.ipaddr","IP Address")
local f_netmask = ProtoField.ipv4("nsdp.netmask","Netmask")
local f_gateway = ProtoField.ipv4("nsdp.gateway","Gateway")
local f_firmwarever_len = ProtoField.uint16("nsdp.firmwarever_len", "Firmware version LEN",base.HEX)
local f_firmwarever = ProtoField.string("nsdp.firmwarever", "Firmware version",FT_STRING)
local speed_flags={
  [0x00]="None",
  [0x01]="10M",
  [0x03]="100M",
  [0x05]="1000M"
}
local f_speedport_1 = ProtoField.uint8("nsdp.speed_port_1","Speed Port 1",base.HEX, speed_flags)
local f_speedport_2 = ProtoField.uint8("nsdp.speed_port_2","Speed Port 2",base.HEX, speed_flags)
local f_speedport_3 = ProtoField.uint8("nsdp.speed_port_3","Speed Port 3",base.HEX, speed_flags)
local f_speedport_4 = ProtoField.uint8("nsdp.speed_port_4","Speed Port 4",base.HEX, speed_flags)
local f_speedport_5 = ProtoField.uint8("nsdp.speed_port_5","Speed Port 5",base.HEX, speed_flags)
local f_speedport_6 = ProtoField.uint8("nsdp.speed_port_6","Speed Port 6",base.HEX, speed_flags)
local f_speedport_7 = ProtoField.uint8("nsdp.speed_port_7","Speed Port 7",base.HEX, speed_flags)
local f_speedport_8 = ProtoField.uint8("nsdp.speed_port_8","Speed Port 8",base.HEX, speed_flags)

--local f_debug = ProtoField.uint8("nsdp.debug", "Debug")
p_nsdp.fields = {f_type,f_source,f_destination,f_seq,f_cmd,f_password,f_newpassword,f_flags,f_model,f_name,f_macinfo,
                 f_ipaddr,f_netmask,f_gateway,f_firmwarever_len,f_firmwarever,f_len,
		 f_speedport_1,f_speedport_2,f_speedport_3,f_speedport_4,f_speedport_5,f_speedport_6,f_speedport_7,f_speedport_8}

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
    elseif cmd == 0x000d then
	tree=subtree:add(f_firmwarever,buf(offset,len))
    elseif cmd==0x0c00 and len==3 then
           local port=buf(offset,1):uint()
	   local link=buf(offset+2,1):uint()
           if (port == 0x01) then
	     tree=subtree:add(f_speedport_1,buf(offset+1,1))
           elseif (port == 0x02) then
	     tree=subtree:add(f_speedport_2,buf(offset+1,1))
           elseif (port == 0x03) then
	     tree=subtree:add(f_speedport_3,buf(offset+1,1))
           elseif (port == 0x04) then
	     tree=subtree:add(f_speedport_4,buf(offset+1,1))
           elseif (port == 0x05) then
	     tree=subtree:add(f_speedport_5,buf(offset+1,1))
           elseif (port == 0x06) then
	     tree=subtree:add(f_speedport_6,buf(offset+1,1))
           elseif (port == 0x07) then
	     tree=subtree:add(f_speedport_7,buf(offset+1,1))
           elseif (port == 0x08) then
	     tree=subtree:add(f_speedport_8,buf(offset+1,1))
           end
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
