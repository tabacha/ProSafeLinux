# ProSafeLinux (psl-cli.py)

Query and set data on GS105E and GS108E Netgear ProSafe switches.

These are known to work:
 * GS105E 1.02.04
 * GS108Ev2 1.00.12
 * GS108Ev3 2.06.08EN (replies come via unicast)

# Using psl-cli.py

     usage: psl-cli.py [-h] [--interface INTERFACE] [--debug]
                   [--timeout TIMEOUT]
                   {discover,exploit,query,query_raw,set} ...

 * Older switch firmware (before 2018?) returns responses to the broadcast address.
 * Newer switch firmware (after 2018?) return responses to the sender.
 * If your interface is **not** eth0 please specify it, when you call *psl.py*.

# Examples

Gives an overview of all available options

    ./psl.py --help

Discover all ProSafe switches on the local network

    ./psl.py --interface eth1 discover

Set 802.1Q VLAN VID for port 4 to 1

    ./psl-cli.py  set --passwd "password" --mac B0:B9:8A:57:F6:56 --vlan_pvid 4 1

Query all ports for their 802.1Q VLAN port VID

    ./psl-cli.py query --mac B0:B9:8A:57:F6:56 vlan_pvid

# Dependencies

Required for cross-platform support of MacOS & Linux.
 - pip install netifaces

# Supported Platforms

"discover" and "query" were recently tested on
 * MacOS 10.15 with python 2.7
 * Raspbian Linux 4.19.66-v7+ with python 2.7

# Known issues

Discovery only identifies the first switch that answers.

Newer switches that have web servers may have "Switch Management Mode" set to "Web browser only", which will result in the switch only responding to discovery requests. To use this software, you may login to the web UI and set "Switch Management Mode" to "Web browser and Plus Utility".

"query all" sometimes produces inconsistent results. More reliable responses seem to occur when you query one item at at time.

# Help wanted

Im sorry I am not active at this project anymore. It is open-source so perhaps you could find soneone who can help you.
 
I have found a security problem with this switch and was very disappointed in the answer from netgear. They need more than 6 Month to fix it and want the ethernet adress of it
 
Because of this, I do not use this switch anymore.
 
If you can read german, please read this two articles:
 
http://www.linux-magazin.de/Blogs/Insecurity-Bulletin/Gastbeitrag-Security-by-Obscurity-bei-Netgear-Switches
http://www.linux-magazin.de/Ausgaben/2012/10/Switch

Please feel free to fork the code and do any push request.

Please contact me if you like to do the new maintainer of the projekt Sven Anders &lt;psl-github2013@sven.anders.im&gt;

# Other similar projects

https://github.com/Z3po/Netgearizer (We are merging code together.)

# Authors

* Asbjørn Sloth Tønnesen 
* Lars Dennis Renneberg Andersen
* Svenne Krap
* Shane Kerr
* Sven Anders
* Steven Bytnar

See also: http://git.asbjorn.biz/?p=gs105e.git;a=summary

It would be nice if you pay attribution to this project if you use this code.

If you like the projekt, you may [![Flattr this git repo](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=tabacha&url=https://github.com/tabacha/ProSafeLinux&title=ProSafeLinux&language=&tags=github&category=software)
