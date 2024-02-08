from socket import *

with socket(AF_INET, SOCK_STREAM) as skt:
    skt.connect(("", 2100))
    skt.sendall(b"GET badurl HTTP/1.0\r\n\r\n")
    print(skt.recv(4096))
    print(skt.recv(4096))
