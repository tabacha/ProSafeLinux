-- create nsdp protocol and its fields
p_nsdp = Proto ("nsdp","Netgear Switch Description Protocol")
-- local f_source = ProtoField.uint16("nsdp.src", "Source", base.HEX)
local f_type = ProtoField.uint16("nsdp.type", "Type", base.HEX)
local f_source = ProtoField.ether("nsdp.src", "Source", base.HEX)
local f_destination = ProtoField.ether("nsdp.dst", "Destination", base.HEX)
local f_seq = ProtoField.uint16("nsdp.seq", "Seq", base.HEX)
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
local f_network = ProtoField.ipv4("nsdp.network","Network")
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
                 f_ipaddr,f_netmask,f_network,f_firmwarever_len,f_firmwarever,
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
  local cmd = 0
  if offset < buf:len() then
    cmd = buf(offset, 2):uint()
    subtree:add(f_cmd,buf(offset, 2))
    offset = offset + 2
  else
    subtree:add(f_cmd, cmd)
  end
  if cmd == 1 then
    subtree:append_text(", init")
    if (ptype==0x0102) then
        subtree:append_text("-response")
	local model_len=buf(offset,2):uint()
	offset=offset+2
	subtree:add(f_model,buf(offset,model_len))
	offset=offset+model_len

	-- cmd==buf(offset,2):uint() ??? cmd == 0x02
	offset=offset+2
        local fixme_len=buf(offset,2):uint()
	offset=offset+2
	offset=offset+fixme_len

	-- cmd==buf(offset,2):uint() ??? cmd == 0x03
	offset=offset+2
	local name_len=buf(offset,2):uint()
	offset=offset+2
	subtree:add(f_name,buf(offset,name_len))
	offset=offset+name_len

	-- cmd==buf(offset,2):uint() ??? cmd == 0x04
	offset=offset+2
	local macinfo_len=buf(offset,2):uint()
	offset=offset+2
	subtree:add(f_macinfo,buf(offset,macinfo_len))
	offset=offset+macinfo_len

	-- cmd==buf(offset,2):uint() ??? cmd == 0x05
	offset=offset+2
	fixme_len=buf(offset,2):uint()
	offset=offset+2
	offset=offset+fixme_len

	-- cmd==buf(offset,2):uint() ??? cmd == 0x06
	offset=offset+2
	local ip_len=buf(offset,2):uint()
	offset=offset+2
	subtree:add(f_ipaddr,buf(offset,ip_len))
	offset=offset+ip_len

	-- cmd==buf(offset,2):uint() ??? cmd == 0x07
	offset=offset+2
	local netmask_len=buf(offset,2):uint()
	offset=offset+2
	subtree:add(f_netmask,buf(offset,netmask_len))
	offset=offset+netmask_len

	-- cmd==buf(offset,2):uint() ??? cmd == 0x08
	offset=offset+2
	local network_len=buf(offset,2):uint()
	offset=offset+2
	subtree:add(f_network,buf(offset,network_len))
	offset=offset+network_len

	-- cmd==buf(offset,2):uint() ??? cmd == 0x0b
	offset=offset+2
	fixme_len=buf(offset,2):uint()
	offset=offset+2
	offset=offset+fixme_len

	-- cmd==buf(offset,2):uint() ??? cmd == 0x0c
	offset=offset+2
	fixme_len=buf(offset,2):uint()
	offset=offset+2
	offset=offset+fixme_len

	-- cmd==buf(offset,2):uint() ??? cmd == 0x0d
	offset=offset+2
	--subtree:add(f_firmwarever_len,buf(offset,2))
	local len=buf(offset,2):uint()
	offset=offset+2
	subtree:add(f_firmwarever,buf(offset,len))
	-- cmd==buf(offset,2):uint() ??? cmd == 0x0e
	-- cmd==buf(offset,2):uint() ??? cmd == 0x0f
    end
  elseif (ptype == 0x0102 and cmd == 0x0c00) then
        subtree:append_text("port-speed-link")
	while (cmd==0x0c00) do
	   local len=buf(offset,2):uint()
	   offset=offset+2
           local port=buf(offset,1):uint()
	   local link=buf(offset+2,1):uint()
           if (port == 0x01) then
	     subtree:add(f_speedport_1,buf(offset+1,1))
           elseif (port == 0x02) then
	     subtree:add(f_speedport_2,buf(offset+1,1))
           elseif (port == 0x03) then
	     subtree:add(f_speedport_3,buf(offset+1,1))
           elseif (port == 0x04) then
	     subtree:add(f_speedport_4,buf(offset+1,1))
           elseif (port == 0x05) then
	     subtree:add(f_speedport_5,buf(offset+1,1))
           elseif (port == 0x06) then
	     subtree:add(f_speedport_6,buf(offset+1,1))
           elseif (port == 0x07) then
	     subtree:add(f_speedport_7,buf(offset+1,1))
           elseif (port == 0x08) then
	     subtree:add(f_speedport_8,buf(offset+1,1))
           end
	   offset=offset+len
	   cmd = buf(offset,2):uint()
	   offset=offset+2
        end
  elseif cmd == 0xa or (ptype == 0x0104 and cmd == 0) then
    if ptype == 0x0103 then
      local pw_len = buf(offset, 2):uint()
      offset = offset + 2
      subtree:add(f_password, buf(offset,pw_len))
      offset = offset + pw_len
      local next_up = buf(offset, 2):uint()
      offset = offset + 2
      if next_up == 0x0009 then
        subtree:append_text(", reset password")
        pw_len = buf(offset, 2):uint()
        offset = offset + 2
        subtree:add(f_newpassword, buf(offset,pw_len))
      else
        subtree:append_text(", login")
      end
    elseif ptype == 0x0104 then
      if buf:len() == offset then
        subtree:append_text(", password changed")
      else
        subtree:append_text(", logged in")
      end
    end
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
