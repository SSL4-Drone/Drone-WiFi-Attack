import os

def selIface():
    if (os.path.exists('./interface.txt')):
        file = open('./interface.txt', 'r')
        iface = file.readline()
        # 파일이 존재하면 읽음
    else:
        iface = input("Input your interface : ")
        file = open('./interface.txt', 'w')
        file.write(iface)
        # 파일이 존재하지 않으면 생성
    file.close()
    return iface