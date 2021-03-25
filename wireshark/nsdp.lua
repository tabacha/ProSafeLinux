-- create nsdp protocol and its fields
p_nsdp = Proto ("nsdp","Netgear Switch Description Protocol")
-- local f_source = ProtoField.uint16("nsdp.src", "Source", base.HEX)
local e_error = ProtoExpert.new("nsdp.error", "Error", expert.group.RESPONSE_CODE, expert.severity.ERROR)
local f_type = ProtoField.uint16("nsdp.type", "Type", base.HEX,{
    [0x101]="Data Request",
    [0x102]="Data Response",
    [0x103]="Change Request",
    [0x104]="Change Response"
})

local t_status = {
    [0x00]="Success",
    [0x01]="Protocol version not supported",
    [0x02]="Command not supported",
    [0x03]="TLV type not supported",
    [0x04]="Invalid TLV length",
    [0x05]="Invalid TLV value",
    [0x06]="Manager IP is blocked by ACL",
    [0x07]="Invalid password",
    [0x08]="Firmware download requested",
    [0x09]="Invalid username",
    [0x0a]="Switch only supports management by browser",
    [0x0d]="Invalid password",
    [0x0e]="3 failed attempts.  Switch is locked for 30 minutes",
    [0x0f]="Switch management disabled.  Use browser to enable",
    [0x81]="TFTP call error",
    [0x82]="TFTP Out of memory",
    [0x83]="Firmware update failed",
    [0x84]="TFTP timed out"
}
local f_status = ProtoField.uint8("nsdp.status", "Status", base.HEX, t_status)
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

local t_cmd = {
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
    [0x0014] = "Enhanced encryption",
    [0x0017] = "Password nonce",
    [0x0018] = "32-bit password hash",
    [0x001a] = "64-bit password hash",
    [0x0400] = "Factory Reset",
    [0x0c00] = "Port status",
    [0x1000] = "Port Traffic Statistic",
    [0x1400] = "Reset Port Traffic Statistic",
    [0x1800] = "Test Cable",
    [0x1c00] = "Cable test result",
    [0x2000] = "VLAN Engine",
    [0x2400] = "VLAN-ID",
    [0x2800] = "802VLAN-ID",
    [0x2c00] = "Delete VLAN",
    [0x3000] = "vlan_pvid",
    [0x3400] = "QoS",
    [0x3800] = "QoS port priority",
    [0x4c00] = "Bandwidth Limit IN",
    [0x5000] = "Bandwidth Limit OUT",
    [0x5400] = "Broadcast filtering",
    [0x5800] = "Broadcast Bandwidth",
    [0x5c00] = "Port Mirror",
    [0x6000] = "Number of available ports",
    [0x6800] = "IGMP Snooping Status",
    [0x6c00] = "Block Unknown Multicasts",
    [0x7000] = "IGMP Header Validation",
    [0x7400] = "Supported TLVs",
    [0x7800] = "Serial number",
    [0x9000] = "Loop detection",
    [0x9400] = "Port Admin Status",
    [0xffff] = "End Request"
}
local f_cmd = ProtoField.uint16("nsdp.cmd", "Command", base.HEX, t_cmd)
local f_fixme0002 = ProtoField.uint16("nsdp.fixme0002", "Fix me 0x0002", base.HEX)
local f_fixme000C = ProtoField.uint8("nsdp.fixme000C", "Fix me 0x000C", base.HEX)
local f_password = ProtoField.string("nsdp.password", "Password", FT_STRING)
local f_enhancedEncryption = ProtoField.uint32("nsdp.enhancedencryption", "Enhanced encryption", base.HEX)
local f_passwordNonce = ProtoField.uint32("nsdp.passwordnonce", "Password nonce", base.HEX)
local f_passhash32 = ProtoField.uint32("nsdp.passwordhash32", "32-bit password hash", base.HEX)
local f_passhash64 = ProtoField.uint64("nsdp.passwordhash64", "64-bit password hash", base.HEX)
local f_newpassword = ProtoField.string("nsdp.newpassword", "New password", FT_STRING)
local f_errcmd = ProtoField.uint16("nsdp.errcmd", "Failed command", base.HEX, t_cmd)
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
local t_speed_flags={
    [0x00]="None",
    [0x01]="10M (half-duplex)",
    [0x02]="10M",
    [0x03]="100M (half-duplex)",
    [0x04]="100M",
    [0x05]="1000M"
}

local t_flow_control={
    [0x00]="Disabled",
    [0x01]="Enabled"
}

local f_speed = ProtoField.uint8("nsdp.speed","Speed",base.HEX, t_speed_flags)
local f_flow = ProtoField.uint8("nsdp.flow_control", "Flow control", base.HEX, t_flow_control)
local f_qos_mode = ProtoField.uint8("nsdp.qos_mode", "QoS mode", base.HEX, {
    [0x01]="Port based",
    [0x02]="802.1p/DSCP based"
})
local t_port_prio = {
    [0x01]="High",
    [0x02]="Medium",
    [0x03]="Normal",
    [0x04]="Low"
}
local f_qos_port_prio = ProtoField.uint8("nsdp.qos_port_prio", "Priority", base.HEX, t_port_prio)
local f_port=ProtoField.uint8("nsdp.port","Port Number")
local f_rec=ProtoField.uint64("nsdp.recived","Bytes received")
local f_send=ProtoField.uint64("nsdp.sent","Bytes sent")
local f_pkt=ProtoField.uint64("nsdp.pkt","Total packets")
local f_bpkt=ProtoField.uint64("nsdp.pkt_bcst","Broadcast packets")
local f_mpkt=ProtoField.uint64("nsdp.pkt_mcst","Multicast packets")
local f_crce=ProtoField.uint64("nsdp.crc_error","CRC errors")
local f_numports=ProtoField.uint8("ndsp.numports","Number of ports")
local f_supportedTLVs=ProtoField.uint64("nsdp.supportedtlvs","Supported TLVs",base.HEX)
local f_bcast_filtering=ProtoField.uint8("nsdp.bcast_filter", "Broadcast filtering", base.HEX, {
    [0x00]="Disabled",
    [0x03]="Enabled"
})
local t_rate_limit={
    [0x00]="No limit",
    [0x01]="512 Kbit/s",
    [0x02]="1 Mbits/s",
    [0x03]="2 Mbits/s",
    [0x04]="4 Mbits/s",
    [0x05]="8 Mbits/s",
    [0x06]="16 Mbits/s",
    [0x07]="32 Mbits/s",
    [0x08]="64 Mbits/s",
    [0x09]="128 Mbits/s",
    [0x0a]="256 Mbits/s",
    [0x0b]="512 Mbits/s",
}
local f_rate_limit=ProtoField.uint8("nsdp.rate_limit", "Rate", base.HEX, t_rate_limit)
local f_port_mirror_src=ProtoField.uint8("nsdp.port_mirror_src", "Source port(s)", base.HEX)
local f_port_mirror_dest=ProtoField.uint8("nsdp.port_mirror_dest", "Destination port", base.HEX)

local f_pvid_vlan=ProtoField.uint16("nsdp.pvid_vlan", "VLAN")
local f_del_vlan=ProtoField.uint16("nsdp.del_vlan", "Delete VLAN")
local f_802_1q_vlan = ProtoField.uint16("nsdp.802_1q_vlan", "802.1q VLAN")
local f_802_1q_ports = ProtoField.uint8("nsdp.802_1q_ports", "802.1q ports", base.HEX)
local f_802_1q_tagged = ProtoField.uint8("nsdp.802_1q_tagged", "802.1q tagged", base.HEX)

local f_cable_test=ProtoField.string("nsdp.cable_test", "Cable test result")
local t_cable_test_status={
    [0x00]="OK",
    [0x01]="No cable",
    [0x02]="Open cable",
    [0x03]="Short circuit",
    [0x04]="Fibre cable",
    [0x05]="Shorted cable",
    [0x06]="Unknown",
    [0x07]="Crosstalk"
}
local f_cable_test_status=ProtoField.uint32("nsdp.cable_test_status", "Status", base.HEX, t_cable_test_status)
local f_cable_test_distance=ProtoField.uint32("nsdp.cable_test_distance", "Distance")

local port_admin_speed={
    [0x00]="Disabled",
    [0x01]="Auto",
    [0x02]="10M (half-duplex)",
    [0x03]="10M (full-duplex)",
    [0x04]="100M (half-duplex)",
    [0x05]="100M (full-duplex)"
}
local f_port_admin_speed = ProtoField.uint8("nsdp.port_admin_speed", "Speed", base.HEX, port_admin_speed)
local f_loop_detection = ProtoField.uint8("nsdp.loop_detection", "Loop detection", base.HEX, {
    [0x00]="Disabled",
    [0x01]="Enabled"
})

local f_serial_num = ProtoField.string("nsdp.serialnum", "Serial number", FT_STRING)

--local f_debug = ProtoField.uint8("nsdp.debug", "Debug")
p_nsdp.experts = {e_error}


p_nsdp.fields = {f_type,f_status,f_source,f_destination,f_seq,f_cmd,f_password,f_newpassword,f_errcmd,
                 f_enhancedEncryption,f_passwordNonce,f_passhash32, f_passhash64,
                 f_fixme0002, f_fixme000C,
                 f_qos_mode, f_qos_port_prio,
                 f_pvid_vlan, f_del_vlan,
                 f_802_1q_vlan, f_802_1q_ports, f_802_1q_tagged,
                 f_cable_test_status, f_cable_test_distance,
                 f_bcast_filtering,f_rate_limit,f_port_admin_speed,
                 f_port_mirror_src, f_port_mirror_dest,
                 f_model,f_name,f_macinfo,f_dhcp_enable,f_port,f_rec,f_send,
                 f_pkt,f_bpkt,f_mpkt,f_crce,f_vlan_engine,f_ipaddr,
                 f_netmask,f_gateway,f_firmwarever_len,f_firmwarever,f_len,
                 f_firmware2ver, f_firmwareactive,
                 f_speed,f_flow,f_location,f_numports,f_supportedTLVs,f_loop_detection,
                 f_serial_num}

-- Build a condensed string of port ranges from a bitmap
function port_list(ports)
    local list = {}
    local lastPort = -1
    local firstPort = -1
    for i=1,9 do
        if bit32.band(ports,0x80) ~= 0 then
            if lastPort ~= (i - 1) then
                list[#list+1] = ","
                list[#list+1] = i
                firstPort = i
            end
            lastPort = i
        elseif lastPort ~= -1 then
            if firstPort ~= lastPort then
                list[#list+1] = "-"
                list[#list+1] = tostring(lastPort)
            end
            firstPort = -1
            lastPort = -1
        end
        ports = bit32.lshift(ports,1)
    end

    if #list == 0 then
        return "None"
    else
        return table.concat(list,"",2)
    end
end

-- nsdp dissector function
function p_nsdp.dissector (buf, pkt, root)
    -- validate packet length is adequate, otherwise quit
    if buf:len() == 0 then return end
    pkt.cols.protocol = p_nsdp.name

    -- create subtree for nsdp
    subtree = root:add(p_nsdp, buf(0))
    local status = 0
    local errcmd = 0
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
    offset = offset + 2
    status = buf(offset,1)
    if status:uint() ~= 0 then
        local status_tree = subtree:add(f_status, status)
        status = status:uint()
        local errmsg=t_status[status]
        if errmsg == nil then
            errmsg = string.format("Unknown error: 0x%02x", status)
        end
        status_tree:add_proto_expert_info(e_error,errmsg)
        errcmd = buf(offset + 2,2)
        subtree:add(f_errcmd, errcmd)
        errcmd = errcmd:uint()
    else
        status = status:uint()
    end
    offset = offset + 6
    subtree:add(f_source, buf(offset,6))
    offset = offset + 6
    subtree:add(f_destination, buf(offset,6))
    offset = offset + 8
    subtree:add(f_seq, buf(offset,2))
    offset = offset + 10
    if status == 0 then
        while offset < buf:len() do
            local cmd = buf(offset, 2):uint()
            local len=buf(offset+2,2):uint()
            local tree=0
            offset = offset + 4
            if cmd == 0x0001 then
                tree=subtree:add(f_model,buf(offset,len))
            elseif cmd == 0x0002 then
                if len==0x02 then
                    tree=subtree:add(f_fixme0002, buf(offset,len))
                else
                    tree=subtree:add(buf(offset,len), "Fix me 0002")
                end
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
            elseif cmd == 0x000c then
                if len==0x01 then
                    tree=subtree:add(f_fixme000C, buf(offset,len))
                else
                    tree=subtree:add(buf(offset,len), "Fix me 000c")
                end
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
            elseif cmd == 0x0014 then
                if len == 4 then
                    tree=subtree:add(f_enhancedEncryption, buf(offset,len))
                else
                    tree=subtree:add(buf(offset,len),"Enhanced encryption?")
                end
            elseif cmd == 0x0017 then
                if len == 4 then
                    tree=subtree:add(f_passwordNonce, buf(offset,4))
                else
                    tree=subtree:add(buf(offset,len),"Password nonce?")
                end
            elseif cmd == 0x0018 and len==4 then
                    tree=subtree:add(f_passhash32, buf(offset,4))
            elseif cmd == 0x001a and len==8 then
                tree=subtree:add(f_passhash64, buf(offset,8))
            elseif cmd==0x0c00 then
                if len==3 then
                    local port = buf(offset,1)
                    local speed = buf(offset+1,1)
                    local flow = buf(offset+2,1)
                    tree=subtree:add(buf(offset,1),string.format("Port status: Port:%u, Speed:%s, Flow control:%s", port:uint(), t_speed_flags[speed:uint()], t_flow_control[flow:uint()]))
                    tree:add(f_port,port)
                    tree:add(f_speed,speed)
                    tree:add(f_flow,flow)
                else
                    tree=subtree:add(buf(offset,1),"Port status?")
                end
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
                local port=buf(offset,1)
                tree=subtree:add(buf(offset,len), string.format("Test Cable - Port %u", port:uint()))
                tree:add(f_port, port)
                -- 1 Byte  Port 01=Port 1...08=Port 8
                -- 1 Byte alway 0x01
            elseif cmd==0x1c00 and len==0x01 then
                local port=buf(offset,1)
                tree=subtree:add(port, string.format("Cable test result? - Port %u", port:uint()))
                tree:add(f_port, port)
                -- 1 Byte Port
            elseif cmd==0x1c00 and len==0x09 then
                local port=buf(offset,1)
                local status=buf(offset+1,4)
                local distance=buf(offset+5,4)
                tree=subtree:add(buf(offset,len), string.format("Cable test result - Port:%d, Status:%s, Fault distance:%dm",
                                                port:uint(),
                                                t_cable_test_status[status:uint()],
                                                distance:uint()))
                tree:add(f_port, port)
                tree:add(f_cable_test_status, status)
                tree:add(f_cable_test_distance, distance)
            elseif cmd==0x2000 and len==0x01 then
                tree=subtree:add(f_vlan_engine,buf(offset,len))
            elseif cmd==0x2800 and len==0x04 then
                local vlan=buf(offset,2)
                local ports=buf(offset+2,1)
                local tagged=buf(offset+3,1)
                tree=subtree:add(buf(offset,len), string.format("802.1q status: VLAN:%u, Ports:%s, Tagged:%s", vlan:uint(), port_list(ports:uint()), port_list(tagged:uint())))
                tree:add(f_802_1q_vlan, vlan)
                tree:add(f_802_1q_ports, ports)
                tree:add(f_802_1q_tagged, tagged)
            elseif cmd==0x2c00 then
                tree=subtree:add(f_del_vlan, buf(offset,2))
            elseif cmd==0x3000 and len==0x03 then
                local port=buf(offset,1)
                local vlan=buf(offset+1,2)
                tree=subtree:add(buf(offset,len), string.format("PVID: Port:%d, VLAN:%u", port:uint(), vlan:uint()))
                tree:add(f_port, port)
                tree:add(f_pvid_vlan, vlan)
            elseif cmd==0x3400 then
                if len==0x00 then
                    tree=subtree:add(buf(offset,len),"QoS mode?")
                else
                    tree=subtree:add(f_qos_mode, buf(offset,len))
                end
            elseif cmd==0x3800 then
                if len==0x00 then
                    tree=subtree:add(buf(offset,len),"QoS port priority?")
                else
                    local port=buf(offset, 1)
                    local prio=buf(offset + 1, 1)

                    tree=subtree:add(buf(offset,len), string.format("QoS port priority - Port:%u, prio: %s", port:uint(), t_port_prio[prio:uint()]))
                    tree:add(f_port, port)
                    tree:add(f_qos_port_prio, prio)
                end
            elseif cmd==0x4c00 then
                if len==0x00 then
                    tree=subtree:add(buf(offset,len),"Ingress rate limit?")
                else
                    local port=buf(offset, 1)
                    local rate=buf(offset + 3, 2)
                    tree=subtree:add(buf(offset,len),string.format("Ingress limit: Port:%u, rate:%s", port:uint(), t_rate_limit[rate:uint()]))
                    tree:add(f_port, port)
                    tree:add(f_rate_limit, rate)
                end
            elseif cmd==0x5000 then
                if len==0x00 then
                    tree=subtree:add(buf(offset,len),"Egress rate limit?")
                else
                    local port=buf(offset, 1)
                    local rate=buf(offset + 3, 2)
                    tree=subtree:add(buf(offset,len),string.format("Egress limit: Port:%u, rate:%s", port:uint(), t_rate_limit[rate:uint()]))
                    tree:add(f_port, port)
                    tree:add(f_rate_limit, rate)
                end
            elseif cmd==0x5400 then
                if len==0x00 then
                    tree=subtree:add(buf(offset,len),"Broadcast filtering?")
                else
                    tree=subtree:add(f_bcast_filtering, buf(offset,len))
                end
            elseif cmd==0x5800 then
                if len==0x00 then
                    tree=subtree:add(buf(offset,len),"Broadcast storm rate?")
                else
                    local port=buf(offset, 1)
                    local rate=buf(offset + 3, 2)
                    tree=subtree:add(buf(offset,len),string.format("Storm control rate: Port:%u, rate:%s", port:uint(), t_rate_limit[rate:uint()]))
                    tree:add(f_port, port)
                    tree:add(f_rate_limit, rate)
                end
            elseif cmd==0x5c00 and len==0x03 then
                local dest=buf(offset,1)
                local src=buf(offset+2,1)
                tree=subtree:add(buf(offset,len), string.format("Port mirroring: Source port(s):%s, Dest port:%u", port_list(src:uint()), dest:uint()))
                tree:add(f_port_mirror_src, src)
                tree:add(f_port_mirror_dest, dest)
            elseif cmd==0x6000 then
                if len==0x01 then
                    tree=subtree:add(f_numports, buf(offset,len))
                else
                    tree=subtree:add(buf(offset,len),"Number of ports?")
                end
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
            elseif cmd == 0x7400 then
                if len==0x08 then
                    tree=subtree:add(f_supportedTLVs, buf(offset,len))
                else
                    tree=subtree:add(buf(offset,len), "Supported TLVs?")
                end
            elseif cmd == 0x7800 then
                if len==0x00 then
                    tree=subtree:add(buf(offset,len),"Serial number?")
                else
                    local serial=buf(offset+1, 13)
                    tree=subtree:add(buf(offset,len),string.format("Serial number: %s", serial:string()))
                    tree:add(f_serial_num, serial)
                end
            elseif cmd == 0x9000 then
                if len==0x00 then
                  tree=subtree:add(buf(offset,len), "Loop detection?")
                else
                  tree=subtree:add(f_loop_detection, buf(offset,len))
                end
            elseif cmd==0x9400 then
                if len==0x03 then
                    local port=buf(offset,1)
                    local speed=buf(offset+1,1)
                    local flow=buf(offset+2,1)
                    tree=subtree:add(buf(offset,len), string.format("Port admin status: Port:%d, Speed:%s, Flow control:%s", port:uint(), port_admin_speed[speed:uint()], t_flow_control[flow:uint()]))
                    tree:add(f_port, port)
                    tree:add(f_port_admin_speed, speed)
                    tree:add(f_flow, flow)
                else
                    tree=subtree:add(buf(offset,len), "Port admin status?")
                end
            else
                local name=t_cmd[cmd]
                if name==nil then
                    name=string.format("CMD:0x%04x", cmd)
                end
                tree=subtree:add(buf(offset,len),name)
            end
            tree:add(f_cmd,buf(offset-4,2))
            tree:add(f_len,buf(offset-2,2))
            tree:add(buf(offset,len),"DATA")
            offset=offset+len
        end
    else
        local len=buf(offset,2):uint()
        if ptype == 0x0104 then
            offset = offset + 2
            subtree:add(buf(offset,len),"DATA")
            offset=offset+len
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
