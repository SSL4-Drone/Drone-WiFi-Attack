from scapy.all import sniff
from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL, EAPOL_KEY

class collEapol:
    keyInfoList = [b'\x00\x8a', b'\x01\x0a', b'\x13\xca'] # M4 = b'\x03\x0a'
        # EAPOL M1, M2, M3 (M4는 사용하지 않음)
    collCheck = [False, False, False]
    pktList = []
    bssid = ''
    
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
        # EAPOL이 모두 수집이 되면 수집 종료
            return True
        else:
            return False

    def runSniff(self):
        sniff(prn=self.eapolCapture, filter='ether proto 0x888e', stop_filter=self.eapolStop)