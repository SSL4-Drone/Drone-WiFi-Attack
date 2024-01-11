import binascii
import struct
from scapy.all import *
from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL

def convPcap2Hashcat(pcapPath:str, hcPath:str):
    MIC=b''
    MAC_AP=''
    MAC_CLIENT=''
    ESSID=''
    NONCE_AP=''
    NONCE_CLIENT=''
    pktList = rdpcap(pcapPath)
    
    for pkt in pktList:
        if pkt.haslayer(Dot11):
            if (pkt.type == 0) and (pkt.subtype == 8):
            # Beacon Frame 처리
                ESSID = pkt.info
                MAC_AP = pkt.addr3.replace(':', '')
            elif pkt.haslayer(EAPOL):
                eapolFrm =  pkt.getlayer(EAPOL)
                keyInfo = eapolFrm[0].load[1:3]
                if (keyInfo == b'\x00\x8a') or (keyInfo == b'\x13\xca'):
                # EAPOL Frame M1, M3 처리
                    NONCE_AP = eapolFrm[0].load[13:45]
                    if MAC_AP == '':
                        MAC_AP = pkt.addr2.replace(':', '')
                    elif MAC_CLIENT == '':
                        MAC_CLIENT = pkt.addr1.replace(':', '')
                elif (keyInfo == b'\x01\x0a'):
                # EAPOL Frame M2 처리
                    #MIC = eapolFrm[0].load[77:93]
                    NONCE_CLIENT = bytes([eapolFrm[0].version])
                    NONCE_CLIENT += bytes([eapolFrm[0].type])
                    NONCE_CLIENT += struct.pack('>H',eapolFrm[0].len)
                    for idx in range(0, len(eapolFrm[0].load)):
                        if (idx >= 77) and (idx <= 92):
                            MIC += bytes([eapolFrm[0].load[idx]])
                            NONCE_CLIENT += b'\x00'
                        else:
                            NONCE_CLIENT += bytes([eapolFrm[0].load[idx]])
                    if MAC_AP == '':
                        MAC_AP = pkt.addr1.replace(':', '')
                    elif MAC_CLIENT == '':
                        MAC_CLIENT = pkt.addr2.replace(':', '')
                        
    MIC = binascii.hexlify(MIC).decode('ascii')
    ESSID = binascii.hexlify(ESSID).decode('ascii')
    NONCE_AP = binascii.hexlify(NONCE_AP).decode('ascii')
    NONCE_CLIENT = binascii.hexlify(NONCE_CLIENT).decode('ascii')
    
    hcFile = open(hcPath, 'w')
    hcFile.write('WPA*02*')
    hcFile.write(MIC)
    hcFile.write('*')
    hcFile.write(MAC_AP)
    hcFile.write('*')
    hcFile.write(MAC_CLIENT)
    hcFile.write('*')
    hcFile.write(ESSID)
    hcFile.write('*')
    hcFile.write(NONCE_AP)
    hcFile.write('*')
    hcFile.write(NONCE_CLIENT)
    hcFile.write('*02\x0A')
    hcFile.close()