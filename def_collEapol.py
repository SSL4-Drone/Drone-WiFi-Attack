from scapy.all import sniff, wrpcap
from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL

keyInfoList = [b'\x00\x8a', b'\x01\x0a', b'\x13\xca', b'\x03\x0a']
collCheck = [False, False, False, False]
pktList = []

def packetHandler(pkt):
    if pkt.haslayer(EAPOL):
        eapolFrm =  pkt.getlayer(EAPOL)
        keyInfo = eapolFrm[0].load[1:3]
        for idx, val in enumerate(keyInfoList):
            if keyInfo == val:
                collCheck[idx] = True
                idx += 1
                print('EAPOL Message '+str(idx)+' Found. (',val,')')
                pktList.append(pkt)
                break
# EAPOL Frame의 Key Information을 비교해 패킷 리스트에 저장

def stopHandler(pkt):
    if False not in collCheck :
        wrpcap('./test.pcap', pktList)
        return True
    else:
        return False
# EAPOL 1~4 모두 수집이 되면 핸들러 종료

def collEapol():
    sniff(prn=packetHandler, filter='ether proto 0x888e', stop_filter=stopHandler)
    # 핸들러 실행

