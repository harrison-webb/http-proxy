# Place your imports here
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

# IMPORTANT!
# Immediately after you create your proxy's listening socket add
# the following code (where "skt" is the name of the socket here):
# skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Without this code the autograder may cause some tests to fail
# spuriously.

while True:
    pass  # TODO: accept and handle connections
