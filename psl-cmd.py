#!/usr/bin/python
# -*- coding: utf-8 -*-
#

import cmd
from psl_class import ProSafeLinux

class NetgearCMD(cmd.Cmd): # {{{
    switch = ProSafeLinux()

    def __splitLine(self,argumentcount,line): # {{{
        splitline = line.split()
        if len(splitline) > argumentcount:
            print 'Too many arguments!'
            return False
        else:
            if len(splitline) < argumentcount:
                count=len(splitline)
                while count < argumentcount:
                    splitline.append(None)
                    count += 1
            if argumentcount == 1:
                return splitline[0]
            return splitline
    # }}}

    def do_discover(self, line): # {{{
        '''Discover the switches available.
        Arguments: interface'''
        iface = self.__splitLine(1,line)
        if iface == None:
            iface = 'eth0'
        self.switch.bind(iface)
        data = self.switch.discover()
        if (data[self.switch.CMD_DHCP]):
            dhcpstr = " DHCP=on"
        print " * %s\t%s\t%s\t%s\t%s" % (data[self.switch.CMD_MAC],
                                         data[self.switch.CMD_IP],
                                         data[self.switch.CMD_MODEL],
                                         data[self.switch.CMD_NAME],
                                         dhcpstr)

    # }}}

    def do_quit(self, line): # {{{
        '''Quit the Application'''
        return True
    # }}}
    do_EOF = do_quit

# }}}

if __name__ == '__main__':
        NetgearCMD().cmdloop()

# vim:filetype=python:foldmethod=marker:autoindent:expandtab:tabstop=4
