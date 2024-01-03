def chkAtkAddr():
    vicAddr = input('Victim MAC (Empty is broadcast) : ')
    if (vicAddr == ''):
        vicAddr = 'FF:FF:FF:FF:FF:FF'
    bssAddr = input('BSSID MAC : ')
    return (vicAddr, bssAddr)