from socket import *

while True:
    message = input()
    with socket(AF_INET, SOCK_STREAM) as skt:
        skt.connect(("", 1234))
        if message.lower() == "exit":
            skt.send(b"disconnecting")
            skt.close()
            break
        skt.send(str.encode(message))
        print(skt.recv(2048))
