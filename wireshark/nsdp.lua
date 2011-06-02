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

--local f_debug = ProtoField.uint8("nsdp.debug", "Debug")
p_nsdp.fields = {f_type,f_source,f_destination,f_seq,f_cmd,f_password,f_newpassword}

-- nsdp dissector function
function p_nsdp.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = p_nsdp.name

  -- create subtree for nsdp
  subtree = root:add(p_nsdp, buf(0))
  local offset = 0
  local ptype = buf(offset,2):uint()
  subtree:add(f_type, ptype)
  offset = offset + 8
  subtree:add(f_source, buf(offset,6))
  offset = offset + 6
  subtree:add(f_destination, buf(offset,6))
  offset = offset + 8
  subtree:add(f_seq, buf(offset,2))
  offset = offset + 10
  local cmd = 0
  if offset < buf:len() then
    cmd = buf(offset, 2):uint()
    offset = offset + 2
  end
  subtree:add(f_cmd, cmd)

  if cmd == 1 then
    subtree:append_text(", init")
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
