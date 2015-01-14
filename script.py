import socket

addr = '169.254.38.91'
port = 7890
sock = socket.socket()

#recv data
def r():
    print "recv'd: "  + sock.recv(1024)

#send data, affixes the CRLF for you
def s(m):
     sock.sendall(msg + "\r\n")

#sends and recvs the msg, basically you can just call this with your command and itll do the rest
def g(m):
    s(m)
    r()
    r()

if __name__ == '__main__':
    sock.connect( (addr,port))
    r()
    r()
    print "setup done"
    #msg = "dll?lib=msvcrt.dll&func=_wfopen&arg0=README.txt&type0=str&arg1=r&type1=str"
    msg = "dll?lib=msvcrt.dll&func=_waccess&arg0=READMYE.txt&type0=str&arg1=0&type1=int"
    #msg = "ls\r\n"
    g(msg)
   # g(msg)
    sock.close()



