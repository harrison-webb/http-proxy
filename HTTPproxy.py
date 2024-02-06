from socket import *
from urllib.parse import urlparse
from enum import Enum
import signal
from optparse import OptionParser
import sys

http_methods = {b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS"}

"""
Big picture:
1. proxy starts up and begins listening for connections
2. Establishes connection with client
3. Proxy reads data from client and ensures client has sent a properly formatted HTTP GET request
    a. HTTP GET requests end with \r\n\r\n
    b. If request from client is malformed or headers aren't properly formatted, return 400 response to client
    c. For valid HTTP requests other than GET, return 501 (not implemented) to client
4. 
"""


# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)


# Request parsing
class ParseError(Enum):
    NOTIMPL = 1
    BADREQ = 2


def parse_request(message: bytes) -> (ParseError, str, int, str, dict):
    host, port, path, headers = None, None, None, None
    error_type = None
    # TODO: you'll need to write a function like this of some kind and test it
    # for your proxy.

    # split message into first line and the rest of the headers
    request_line, headers_text = message.split(b"\r\n", 1)
    method, url, http_version = request_line.split(" ")

    # Request line validation:

    # Bad request if request line doesn't consist of "<method> <url> <http version>"
    if len(request_line) != 3:
        return (ParseError.BADREQ, None, None, None, None)

    # validate HTTP method
    if method not in http_methods:
        return (ParseError.BADREQ, None, None, None, None)
    if method != b"GET":
        error_type = ParseError.NOTIMPL

    # validate url, set host, port, and path variables
    url_parse = urlparse(url)
    if url_parse.scheme != b"http" or url_parse.netloc == b"" or url_parse.path == b"":
        return (ParseError.BADREQ, None, None, None, None)

    path = url_parse.path  # set path
    # try to split into [hostname, port_number]
    hostname_and_port = url_parse.netloc.split(b":")
    host = hostname_and_port[0]
    if hostname_and_port[1]:
        port = hostname_and_port[1]
    else:
        port = 80

    # validate HTTP version
    if http_version != b"HTTP/1.0":
        return (ParseError.BADREQ, None, None, None, None)

    # Headers validation:
    # TODO

    return None, host, port, path, headers


notimplreq = (ParseError.NOTIMPL, None, None, None, None)
badreq = (ParseError.BADREQ, None, None, None, None)


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
    # bind socket to specified address + port and start it up
    listen_skt.bind((address, port))
    listen_skt.listen()
    print("Server started")

    # establish connection with client
    connection_skt, client_address = listen_skt.accept()

    # revc from client until termination sequence is sent
    client_request = b""
    while True:
        data = connection_skt.recv(10)
        print(f"received from client: {data}")
        client_request += data
        if client_request.endswith(b"\r\n\r\n"):
            print("breaking from loop")
            break

    # parse HTTP request
    print(client_request)


while True:
    pass  # TODO: accept and handle connections
