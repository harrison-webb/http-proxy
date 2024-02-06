from socket import *
import signal
from optparse import OptionParser
import sys


# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)


# TODO: Put function definitions here


# Start of program execution
# Parse out the command line server address and port number to listen to
parser = OptionParser()
parser.add_option("-p", type="int", dest="serverPort")
parser.add_option("-a", type="string", dest="serverAddress")
(options, args) = parser.parse_args()

port = options.serverPort
address = options.serverAddress
if address is None:
    address = "localhost"
if port is None:
    port = 2100

# Set up signal handling (ctrl-c)
signal.signal(signal.SIGINT, ctrl_c_pressed)

# TODO: Set up sockets to receive requests
with socket(AF_INET, SOCK_STREAM) as listen_skt:
    listen_skt.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    """
    1. Create a TCP socket for listening for incoming connections.
    2. Bind that socket to the address and port for which it should accept connections
    3. Tell the OS that we plan to accept connections on this socket by calling listen() on it.
    4. Run a loop that calls accept() on the listening socket. Each call to accept() returns a new socket connected to the client
    5. Call recv() and send() to transfer byte strings back and forth to the client.
    6. Call skt.close(). 1 (Implict due to the end of the with block.) Call listen_socket.close().
    """
    # bind socket to port 1234 and start it up
    listen_skt.bind(("", 1234))
    listen_skt.listen()
    print("Server started")

    while True:
        # establish connection with client
        connection_skt, client_address = listen_skt.accept()

        data = connection_skt.recv(2048)
        print(f"received from client: {data}")
        connection_skt.send(b"From server: I hear you loud and clear")
        connection_skt.close()


# IMPORTANT!
# Immediately after you create your proxy's listening socket add
# the following code (where "skt" is the name of the socket here):
# skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Without this code the autograder may cause some tests to fail
# spuriously.

while True:
    pass  # TODO: accept and handle connections
