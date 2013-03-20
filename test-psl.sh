#!/bin/sh

NAME=name$(date +%s)
./psl-cli.py --interface $INTERFACE discover
./psl-cli.py --interface $INTERFACE query --mac $MAC all
./psl-cli.py --interface $INTERFACE set --mac $MAC --passwd $PW --name $NAME
./psl-cli.py --interface $INTERFACE discover |grep $NAME
if [ "$?" != "0" ] ; then 
    echo "Name not set!"
fi
./psl-cli.py --interface $INTERFACE set --mac $MAC --passwd $PW --dhcp off --ip 192.168.11.117 --netmask 255.255.255.0 --gateway 192.168.11.2
./psl-cli.py --interface $INTERFACE query --mac $MAC dhcp ip gateway netmask
./psl-cli.py --interface $INTERFACE set --mac $MAC --passwd $PW --dhcp off --ip 192.168.11.116 --netmask 255.255.255.0 --gateway 192.168.11.1
./psl-cli.py --interface $INTERFACE query --mac $MAC dhcp ip gateway netmask
./psl-cli.py --interface $INTERFACE set --mac $MAC --passwd $PW --dhcp on
./psl-cli.py --interface $INTERFACE query --mac $MAC dhcp ip gateway netmask
