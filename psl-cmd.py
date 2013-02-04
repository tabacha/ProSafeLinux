#!/usr/bin/python
# -*- coding: utf-8 -*-
#

import cmd
from psl_class import ProSafeLinux

class NetgearCMD(cmd.Cmd): # {{{
    switch = ProSafeLinux()
    selectedswitch = {}
    discovereddata = {}

    def __splitLine(self,argumentcount,line): # {{{
        splitline = line.split()
        if len(splitline) > argumentcount and argumentcount != 0:
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
        self.discovereddata = data
        for entry in data.keys():
            print(entry.get_name() + ': ' + data[entry])
    # }}}

    def do_selectSwitch(self, line): # {{{
        '''Select a switch by IP you wanna use all through the session'''
        switchip = self.__splitLine(1,line)
        if switchip == None:
            print('Please give a IP')
            return False
        else:
            if switchip == self.discovereddata[self.switch.CMD_IP]:
                self.selectedswitch = { "ip" : self.discovereddata[self.switch.CMD_IP],
                                        "mac" : self.discovereddata[self.switch.CMD_MAC] }
            else:
                print('No valid ip given...')
                return False
    # }}}

    def do_query(self, line): # {{{
        """Query Values from Switch.
        If no query command is given it prints out the possibilities"""
        querycmds = self.switch.get_query_cmds()
        query = self.__splitLine(0,line)
        if len(query) == 0:
            for cmd in list(querycmds):
                print str(cmd.get_name())
            return False
        else:
            self.switch.query(query, self.selectedswitch['mac'], 'storefunc')
            for key in self.switch.outdata.keys():
                print("%s - %s" % (key.get_name(), self.switch.outdata[key]))

    # }}}

    def do_quit(self, line): # {{{
        '''Quit the Application'''
        return True
    do_EOF = do_quit
    # }}}

    def do_exploitPassword(self, line): # {{{
        '''Exploit the switches password and set a new one'''
        newpass = self.__splitLine(1,line)
        if newpass == None:
            print('Please give a new password')
            return False
        else:
            self.switch.passwd_exploit(self.selectedswitch['mac'], newpass, 'transfunc')
    # }}}

# }}}

if __name__ == '__main__':
        NetgearCMD().cmdloop()

# vim:filetype=python:foldmethod=marker:autoindent:expandtab:tabstop=4
