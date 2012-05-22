#!/bin/sh
wireshark -R ip.addr==255.255.255.255 -X lua_script:./nsdp.lua $*
