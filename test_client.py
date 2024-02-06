from socket import *

with socket(AF_INET, SOCK_STREAM) as skt:
    skt.connect(("", 2100))
    skt.send(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    skt.send(b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n")
    skt.send(b"\r\n")
    skt.close()
