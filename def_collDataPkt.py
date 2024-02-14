import binascii
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11CCMP
from scapy.all import *

from cls_collPcapFile import collPcap
from cls_ccmp import ccmp
from def_getKey import getPTK, getPMK, getGTK
from def_atkHole196 import bytes2mac


class collData:
    TK = ''
    GTK = ''
    STN_MAC = ''
    BROAD_MAC = 'FF:FF:FF:FF:FF:FF'
    pktList = []
    
    def dataCapture(self, pkt):
        if pkt.haslayer(Dot11):
            if pkt.haslayer(Dot11CCMP):
                if (pkt.type == 2) and (pkt.subtype != 4) and (pkt.subtype != 12):
                    # (QoS) Data Frame이고, (QoS) Null Data가 아니면
                    
                    #print(binascii.hexlify(pkt.data).decode('ascii').upper())
                    PN = bytes([pkt.PN5,pkt.PN4,pkt.PN3,pkt.PN2,pkt.PN1,pkt.PN0])
                    pkt.addr1 = str(pkt.addr1).upper()
                    pkt.addr2 = str(pkt.addr2).upper()
                    pkt.addr3 = str(pkt.addr3).upper()
                    rawData = pkt.data[:-8]
                    
                    if "to-DS" in pkt.FCfield : # AP한테 감. (TK)
                        # addr2 = SRC_MAC / addr3 = DST_MAC
                        if (pkt.addr2 == self.STN_MAC): # -> TK
                            print(pkt.addr2 + ' -> '+ pkt.addr3)
                            if ccmp.decrypt(self.TK, rawData, pkt.addr2, PN) == True:
                                self.pktList.append(pkt)
                    elif "from-DS" in pkt.FCfield : # STN한테 감. (TK/GTK) 
                        # addr3 = SRC_MAC / addr1 = DST_MAC
                        if (pkt.addr3 == self.BROAD_MAC) or (pkt.addr1 == self.BROAD_MAC): # -> GTK
                            print(pkt.addr3 + ' -> '+ pkt.addr1)
                            if ccmp.decrypt(self.GTK, rawData, pkt.addr2, PN) == True:
                                self.pktList.append(pkt)
                        elif (pkt.addr3 == self.STN_MAC) or (pkt.addr1 == self.STN_MAC): # -> TK
                            print(pkt.addr3 + ' -> '+ pkt.addr1)
                            if ccmp.decrypt(self.TK, rawData, pkt.addr2, PN) == True:
                                self.pktList.append(pkt)

    def runSniff(self):
        sniff(prn=self.dataCapture)
        
def collDataPkt(pcapPath:str, pwd:str):
    clsPcap = collPcap()
    clsPcap.read(pcapPath, hashcatFlag=False)

    pmk = getPMK(clsPcap.ESSID, pwd)
    ptk = getPTK(pmk, clsPcap.MAC_AP, clsPcap.MAC_CLIENT, clsPcap.NONCE_AP, clsPcap.NONCE_CLIENT)
    tk = ptk[32:48]
    print('TK : '+binascii.hexlify(tk).decode('ascii'))
    # PMK -> PTK -> TK (Unicast Key)
    kek = ptk[16:32]
    print('KEK : '+binascii.hexlify(kek).decode('ascii'))
    gtk = getGTK(kek, clsPcap.GTK_ENCDATA)[0]
    if gtk == None:
        return False
    # PMK -> PTK -> KEK -> GTK (Broadcast/Multicast Key)
    
    clsData = collData()
    clsData.TK = tk
    clsData.GTK = gtk
    clsData.STN_MAC = bytes2mac(clsPcap.MAC_CLIENT)
    clsData.runSniff()
    
    pktList = []
    pktFile = rdpcap(pcapPath)
    for pkt in pktFile:
        pktList.append(pkt)
    pktList += clsData.pktList
    wrpcap('./decrypted_packet.pcap', pktList)
    print(' Packet save. (./decrypted_packet.pcap)')

