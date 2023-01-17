#TS server
import socket as mysoc
import pickle
import sys
import hmac
import hashlib

#file_name = sys.argv[1]

def ts():
    try:
        astssd = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)

    except mysoc.error as err:
        print('[TS]: {}\n'.format("socket open error ", err))
    
    try:
        ctssd = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)

    except mysoc.error as err:
        print('[TS]: {}\n'.format("socket open error ", err))

    try:
        file_TABLE = "MIHIR-TLDS1.txt"
        frTABLE = open(file_TABLE, "r")
    except IOError as err:
        print('{} \n'.format("File Open Error ",err))
        print("Please ensure table file exists in source folder")
        exit()

    TS_table = {}
    for line in frTABLE:
        entry = line.split(' ')
        formatted_entry = []
        for item in entry:
            if item != ' ' and item != '':
                if item.endswith('\n'):
                    item = item[:-1]
                formatted_entry.append(item)

        if formatted_entry[0] not in TS_table:
            TS_table[formatted_entry[0]] = {}
        TS_table[formatted_entry[0]]['ip'] = formatted_entry[1]
        TS_table[formatted_entry[0]]['flag'] = formatted_entry[2]

    try:
        file_KEY = "MIHIR-KEY1.txt"
        frKEY = open(file_KEY, "r")
    except IOError as err:
        print('{} \n'.format("File Open Error ",err))
        print("Please ensure key file exists in source folder")
        exit()
    key = ""
    for line in frKEY:
       key = line.strip()
       break
    
    if not key:
        print("No key found")
        exit()
    server_binding=('',5678)
    astssd.bind(server_binding)
    astssd.listen(1)
    host=mysoc.gethostname()
    print("[S]: Server host name is: ",host)
    localhost_ip=(mysoc.gethostbyname(host))
    print("[S]: Attempting to connect to as.\n[S]: Server IP address is  ",localhost_ip)
    assd,addr=astssd.accept()
    print ("[S]: Got a connection request from a client at", addr)

    server_binding=('',5679)
    ctssd.bind(server_binding)
    ctssd.listen(1)
    host=mysoc.gethostname()
    print("[S]: Server host name is: ",host)
    localhost_ip=(mysoc.gethostbyname(host))
    print("[S]: Attempting to connect to as.\n[S]: Server IP address is  ",localhost_ip)
    ctsd,addr=ctssd.accept()
    print ("[S]: Got a connection request from a client at", addr)

    while True:
        data = (assd.recv(100))
        if not data: break
        challenge=pickle.loads(data)
        digest = hmac.new(key.encode(),challenge.encode("utf-8"),hashlib.sha1)
        assd.send(pickle.dumps(digest.hexdigest()))
        auth=pickle.loads(assd.recv(100))
        if "fail" in auth:
            continue

        hnstring=pickle.loads(ctsd.recv(100))
        if not hnstring: continue
        entry = ''
        if hnstring in TS_table:
            entry = hnstring + ' ' + TS_table[hnstring]['ip'] + ' ' + TS_table[hnstring]['flag']
        else:
            entry = hnstring + " - Error:HOST NOT FOUND"
        ctsd.send(pickle.dumps(entry))
    frTABLE.close()
    frKEY.close()
    astssd.close()
    ctssd.close()

ts()