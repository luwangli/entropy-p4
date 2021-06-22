#!/usr/bin/python

from scapy.all import Ether, IP, sendp, get_if_hwaddr, get_if_list, TCP, Raw
import sys
import random, string

def pktge():
	p = Ether()/IP(dst="10.0.2.2")/TCP(dport=1234)/"1"
	sendp(p,count=1)
	p = Ether()/IP(dst="10.0.3.4")/TCP(dport=1234)/"2"
	sendp(p,count=1)
	p = Ether() / IP(dst="10.0.4.4") / TCP(dport=1234) / "3"
	sendp(p, count=1)
	p = Ether() / IP(dst="10.0.11.3") / TCP(dport=1234) / "4"
	sendp(p, count=1)
#    p = Ether() / IP(dst="10.0.11.3") / TCP(dport=1234) / "4"
 #   sendp(p, count=1)

if __name__ == '__main__':
	pktge()

