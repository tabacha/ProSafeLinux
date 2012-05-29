# Setup 

As a superuser set a default route to the interface where the switch is connected:

##Example:

    ip route add 255.255.255.255 dev eth1

If your interface is **not** eth0 please specify it, when you call *psl-cmd.py*.

##Example:

    ./psl-cmd.py --interface eth1 discover

# DEPENDENCYS


http://code.google.com/p/ipaddr-py/downloads/detail?name=3144.tar.gz

# Help wanted

* If you have a switch which show CRC errors on statistic page,
* If you have a cable which is bad, and the cable test report it,

Please feel free to fork the code and do any push request.

Please contact me Sven Anders <psl-github2012@sven.anders.im>

# Authors

* Asbjørn Sloth Tønnesen 
* Lars Dennis Renneberg Andersen
* Svenne Krap
* Sven Anders

# License

I have tried to contact the other authors (on 22th of May 2012), but with no success, perhabs they 
will answer soon.

My (Sven Anders) contribution is public domain. It would be nice if you pay attribution to this 
project if you use this code.
