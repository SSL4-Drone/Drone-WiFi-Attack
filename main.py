
import os, sys
if os.geteuid() != 0:
    sys.exit("Only root can run this script.")
    
from scapy.all import conf
from def_selIface import selIface
from def_selMac import selMac
from def_atkDeauth import atkDeauth
from def_atkCSA import atkCSA
from def_atkHole196 import atkHole196
from def_collPkt import collPkt
from def_collDataPkt import collDataPkt
from def_convPcap2Hashcat import convPcap2Hashcat

# sudo pip install --upgrade pip
# sudo pip install https://github.com/secdev/scapy/archive/refs/heads/master.zip
# sudo pip install pycrypto
# sudo pip install pycryptodomex

while(True):
    os.system('clear')
    conf.iface = selIface()
    print('')
    print('██████  ██████   ██████  ███    ██ ███████')                                                                         
    print('██   ██ ██   ██ ██    ██ ████   ██ ██')                                                                              
    print('██   ██ ██████  ██    ██ ██ ██  ██ █████')                                                                           
    print('██   ██ ██   ██ ██    ██ ██  ██ ██ ██')                                                                              
    print('██████  ██   ██  ██████  ██   ████ ███████')                                                                         
    print('')                                                                                                               
    print('██     ██ ██ ██████  ███████ ██      ███████ ███████ ███████      █████  ████████ ████████  █████   ██████ ██   ██') 
    print('██     ██ ██ ██   ██ ██      ██      ██      ██      ██          ██   ██    ██       ██    ██   ██ ██      ██  ██')  
    print('██  █  ██ ██ ██████  █████   ██      █████   ███████ ███████     ███████    ██       ██    ███████ ██      █████')   
    print('██ ███ ██ ██ ██   ██ ██      ██      ██           ██      ██     ██   ██    ██       ██    ██   ██ ██      ██  ██ ') 
    print(' ███ ███  ██ ██   ██ ███████ ███████ ███████ ███████ ███████     ██   ██    ██       ██    ██   ██  ██████ ██   ██ ')
    print('(Made by. 2N(nms200299) / SSL(Stealien Security Leader) Study)')
    print('')
    print('')
    print('# [Disconnect Attack]')
    print('     1. Deauth Attack (~WPA2, Non PMF)')
    print('     2. CSA Attack (~WPA3, PMF)')
    print('# [EAPOL Collect]')
    print('     3. EAPOL Collect (Normal)')
    print('     4. EAPOL Collect (Deauth)')
    print('     5. EAPOL Collect (CSA)')
    print('# [Hashcat Option]')
    print('     6. Convert Pcap to HC22000 File')
    print('# [Packet Injection]')
    print('     7. Hole196 (GTK) - ARP Spoofing')
    print('# [Decrypt 802.11]')
    print('     8. Decrypt 802.11 Packet (TK, GTK)')
    print('# [Other]')
    print('     9. Change LAN Interface')
    print('     10. Change LAN Interface Channel')
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
    # 3. EAPOL Collect (Normal)
        pcapPath = input('Output file (*.pcap) path : ')
        collPkt(selMac(bssFlag=True)[1], pcapPath)
        
    elif choice == '4':
    # 4. EAPOL Collect (Deauth)
        pcapPath = input('Output file (*.pcap) path : ')
        vicMac, bssMac = selMac(vicFlag=True, bssFlag=True)
        collPkt(bssMac, pcapPath, vicAddr=vicMac, atkOption=1)
        
    elif choice == '5':
    # 5. EAPOL Collect (CSA)
        pcapPath = input('Output file (*.pcap) path : ')
        vicMac, bssMac = selMac(vicFlag=True, bssFlag=True)
        collPkt(bssMac, pcapPath, vicAddr=vicMac, atkOption=2)
        
    elif choice == '6':
    # 6. Convert Pcap to HC22000 File
        pcapPath = input('Input file path (*.pcap) : ')
        hcPath = input('Output file (*.hc22000) path : ')
        convPcap2Hashcat(pcapPath, hcPath)
        
    elif choice == '7':
    # 7. Hole196 (GTK)
        pcapPath = input('Input file path (*.pcap) : ')
        pwd = str(input('Input WiFi Password : '))
        atkHole196(pcapPath, pwd)

    elif choice == '8':
    # 8. Decrypt 802.11 Packet (TK, GTK)
        #pcapPath = input('Input file path (*.pcap) : ')
        #pwd = str(input('Input WiFi Password : '))
        pcapPath = './test.pcap'
        pwd = '123456789'
        collDataPkt(pcapPath, pwd)

    elif choice == '9':
    # 9. Change LAN Interface
        selIface(reSelFlag=True)
        
    elif choice == '10':
    # 10. Change LAN Interface Channel
        channel = input("Set interface channel : ")
        os.system('sudo iwconfig '+conf.iface+' ch '+channel)
        
    else:
    # Invalid Option
        print('Invalid Option.')
    
    try:
        input('Press Enter key to continue ...')
    except:
        pass