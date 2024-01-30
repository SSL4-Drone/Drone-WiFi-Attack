import binascii
import struct
from scapy.all import *
from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL

class collPcap:
    MIC=b''
    MAC_AP=''
    MAC_CLIENT=''
    ESSID=''
    NONCE_AP=''
    NONCE_CLIENT=''
    GTK_ENCDATA=''
    
    def read(self, pcapPath:str, hashcatFlag=False):
        pktList = rdpcap(pcapPath)
        
        for pkt in pktList:
            if pkt.haslayer(Dot11):
                if (pkt.type == 0) and (pkt.subtype == 8):
                # Beacon Frame 처리
                    self.ESSID = pkt.info
                    self.MAC_AP = pkt.addr3.replace(':', '')
                elif pkt.haslayer(EAPOL):
                    eapolFrm =  pkt.getlayer(EAPOL)
                    keyInfo = bytes(eapolFrm[0])[5:7] # 이전 scapy : keyInfo = eapolFrm[0].load[1:3] 
                    if (keyInfo == b'\x00\x8a') or (keyInfo == b'\x13\xca'):
                    # EAPOL Frame M1, M3 처리 (ANonce)
                        self.NONCE_AP = bytes(eapolFrm[0])[17:49] # 이전 scapy : self.NONCE_AP = eapolFrm[0].load[13:45]
                        if self.MAC_AP == '':
                            self.MAC_AP = pkt.addr2.replace(':', '')
                        elif self.MAC_CLIENT == '':
                            self.MAC_CLIENT = pkt.addr1.replace(':', '')
                        
                        if (keyInfo == b'\x13\xca'):
                        # EAPOL Frame M3 처리 (GTK 관련 WPA KeyData)
                            self.GTK_ENCDATA = bytes(eapolFrm[0])[99:]
                            
                    elif (keyInfo == b'\x01\x0a'):
                    # EAPOL Frame M2 처리 (SNonce)
                        self.NONCE_CLIENT = bytes([eapolFrm[0].version])
                        self.NONCE_CLIENT += bytes([eapolFrm[0].type])
                        self.NONCE_CLIENT += struct.pack('>H',eapolFrm[0].len)
                        for idx in range(4, len(bytes(eapolFrm[0]))):
                            if (idx >= 81) and (idx <= 96):
                                self.MIC += bytes(eapolFrm[0])[idx].to_bytes(1, byteorder="big")
                                self.NONCE_CLIENT += b'\x00'
                            else:
                                self.NONCE_CLIENT += bytes(eapolFrm[0])[idx].to_bytes(1, byteorder="big")
                        if self.MAC_AP == '':
                            self.MAC_AP = pkt.addr1.replace(':', '')
                        elif self.MAC_CLIENT == '':
                            self.MAC_CLIENT = pkt.addr2.replace(':', '')
        

        if hashcatFlag == True:
            self.MIC = binascii.hexlify(self.MIC).decode('ascii')
            self.ESSID = binascii.hexlify(self.ESSID).decode('ascii')
            self.NONCE_AP = binascii.hexlify(self.NONCE_AP).decode('ascii')
            self.NONCE_CLIENT = binascii.hexlify(self.NONCE_CLIENT).decode('ascii')
            # ▲ HC22000에서 사용 (EAPOL M2에서 802.1X Authentication 페이로드 전체에서 MIC를 0x00으로 치환한 값)
        else:
            self.MAC_CLIENT = bytes.fromhex(self.MAC_CLIENT)
            self.MAC_AP = bytes.fromhex(self.MAC_AP)
            # ▲ str 형을 bytes 형으로 변환
            self.ESSID = str(self.ESSID, 'utf-8')
            # ▲ bytes 형을 str 형으로 변환
            self.NONCE_CLIENT = self.NONCE_CLIENT[17:49]
            # ▲ 802.1X Authentication 페이로드 전체에서 NONCE 값만 슬라이싱
        