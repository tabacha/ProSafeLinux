#!/bin/sh

NAME=name$(date +%s)
./psl.py --interface $INTERFACE discover
./psl.py --interface $INTERFACE query --mac $MAC all
./psl.py --interface $INTERFACE set --mac $MAC --passwd $PW --name $NAME
./psl.py --interface $INTERFACE discover |grep $NAME
if [ "$?" != "0" ] ; then 
    echo "Name not set!"
fi
./psl.py --interface $INTERFACE set --mac $MAC --passwd $PW --dhcp off --ip 192.168.11.117 --netmask 255.255.255.0 --gateway 192.168.11.2
./psl.py --interface $INTERFACE query --mac $MAC dhcp ip gateway netmask
./psl.py --interface $INTERFACE set --mac $MAC --passwd $PW --dhcp off --ip 192.168.11.116 --netmask 255.255.255.0 --gateway 192.168.11.1
./psl.py --interface $INTERFACE query --mac $MAC dhcp ip gateway netmask
./psl.py --interface $INTERFACE set --mac $MAC --passwd $PW --dhcp on
./psl.py --interface $INTERFACE query --mac $MAC dhcp ip gateway netmask