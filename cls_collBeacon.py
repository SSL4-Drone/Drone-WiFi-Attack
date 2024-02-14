from scapy.layers.dot11 import Dot11
from scapy.all import sniff

class collBeacon:
    bssid = ''
    pkt = ''
    
    def __init__(self) -> None:
        pass
    
    def beaconCapture(self, pkt):
    # BEACON 프레임 수집
        if pkt.haslayer(Dot11):
            dot11Frm = pkt.getlayer(Dot11)
            if (dot11Frm.type == 0) and (dot11Frm.subtype == 8):
                if str(dot11Frm.addr3).upper() == self.bssid:
                    self.pkt = pkt
                    print('Beacon Frame Found. ('+str(pkt.info)+', BSS='+self.bssid+')')

    def beaconStop(self, pkt):
    # BEACON 프레임 수집 종료
        if self.pkt != '':
            return True
        else:
            return False
        
    def runSniff(self):
        self.bssid = self.bssid.upper()
        sniff(prn=self.beaconCapture, stop_filter=self.beaconStop)