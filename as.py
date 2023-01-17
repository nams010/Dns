#RS server
import socket as mysoc
import pickle
import sys
import hmac
import hashlib

tlds1 = "TLDS1" #sys.argv[1]
tlds2 = "TLDS2" #sys.argv[2]

def rs():
    #initialize AS socket
    try:
        assd = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)

    except mysoc.error as err:
        print('[RS]{} \n'.format("RS server socket open error ", err))

    #[tlds1 socket]
    try:
        astotscom=mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)

    except mysoc.error as err:
        print('{} \n'.format("socket open error ", err))

    #[tlds2 socket]
    try:
        astotsedu=mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)

    except mysoc.error as err:
        print('{} \n'.format("socket open error ", err))

    AS_table = {}
    host=mysoc.gethostname()
    com = tlds1
    AS_table[com] = {'ip': mysoc.gethostbyname(host), 'flag':'NS'}
    edu = tlds2
    AS_table[edu] = {'ip': mysoc.gethostbyname(host), 'flag':'NS'}

    try:
        sa_sameas_myaddr = AS_table[com]['ip']
        portTLDS1 = 5678
        server_binding = (sa_sameas_myaddr, portTLDS1)
        astotscom.connect(server_binding)
    except mysoc.error as err:
        print('{} \n'.format("TLDS1 connect error "), err)
        exit()

    try:
        sa_sameas_myaddr = AS_table[edu]['ip']
        portTLDS2 = 5677
        server_binding = (sa_sameas_myaddr, portTLDS2)
        astotsedu.connect(server_binding)
    except mysoc.error as err:
        print('{} \n'.format("TLDS2 connect error "), err)
        exit()
    server_binding = ('',50008)
    assd.bind(server_binding)
    assd.listen(1)
    host=mysoc.gethostname()
    print("[S]: Authentication Server host name is: ",host)
    localhost_ip=(mysoc.gethostbyname(host))
    print("[S]: Attempting to connect to client.\n[S]: Server IP address is  ",localhost_ip)
    casd,addr=assd.accept()
    print ("[S]: Got a connection request from a client at", addr)

    server=""
    #Authentication Loop
    while True:
        data=casd.recv(100)
        if not data: break
        digest=pickle.loads(data)
        key = digest[0]
        challenge = digest[1]
        dvalid=hmac.new(key.encode(),challenge.encode("utf-8"),hashlib.sha1)
        astotscom.send(pickle.dumps(challenge))
        digestTLDS1=pickle.loads(astotscom.recv(100))
        astotsedu.send(pickle.dumps(challenge))
        digestTLDS2=pickle.loads(astotsedu.recv(100))
        if dvalid.hexdigest()==digestTLDS1:
            server="TLDS1"
            astotscom.send(pickle.dumps("pass"))
            astotsedu.send(pickle.dumps("fail"))
        elif dvalid.hexdigest()==digestTLDS2:
            server="TLDS2"
            astotscom.send(pickle.dumps("fail"))
            astotsedu.send(pickle.dumps("pass"))
        else:
            server="error"
            astotscom.send(pickle.dumps("fail"))
            astotsedu.send(pickle.dumps("fail"))
        casd.send(pickle.dumps(server))

    # close everything
    astotscom.close()
    astotsedu.close()
    assd.close()

rs()