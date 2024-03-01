from socket import *

with socket(AF_INET, SOCK_STREAM) as skt:
    skt.connect(("", 2100))
    skt.sendall(
        b"GET http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:50.0) Firefox/50.0\r\n\r\n"
    )
    print(skt.recv(4096))
    print(skt.recv(4096))
