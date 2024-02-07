from socket import *
from urllib.parse import urlparse
from enum import Enum
import re
import signal
from optparse import OptionParser
import sys
import logging

logging.basicConfig(level=logging.ERROR)

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
    """Parse and validate a HTTP request string

    Args:
        message (bytes): HTTP request string
        str (str): hostname
        int (int): port number
        str (str): path
        dict (dict): dictionary of <header name>: <header value>

    Returns:
        5-tuple: (Optional(ParseError), Optional(hostname), Optional(port number), Optional(path), Optional(header dictionary))
    """
    host, port, path, headers = None, None, None, {}
    error_type = None

    # split message into first line and the rest of the headers
    request_line, headers_data = message.split(b"\r\n", 1)

    ### Request line validation:
    # Bad request if request line doesn't consist of "<method> <url> <http version>"
    if len(request_line.split(b" ")) != 3:
        return (ParseError.BADREQ, None, None, None, None)
    method, url, http_version = request_line.split(b" ")

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
    # if hostname doesn't specify port, default to 80
    hostname_and_port = url_parse.netloc.split(b":")
    host = hostname_and_port[0]
    if len(hostname_and_port) == 2:
        port = int(hostname_and_port[1])
    else:
        port = 80

    # validate HTTP version
    if http_version != b"HTTP/1.0":
        return (ParseError.BADREQ, None, None, None, None)

    ### Parse + validate other headers:
    # split on newline to isolate each `<header name: <header value>`
    headers_arr = headers_data.split(b"\r\n")
    headers_arr = [x for x in headers_arr if x.strip()]  # remove whitespace lines
    for line in headers_arr:
        # pattern to match valid header. A valid header is "<name>: <value>"
        # there is no whitespace before the colon, and one space after it
        # <value> is allowed to contain a colon, as long as it has text on both sides of it
        if re.search(r"^[^:]+[^\s]: (([^:]+)|(.*\S:\S.*))$".encode(), line):
            name, value = line.split(b":", 1)
        else:
            # invalid header if it does not match the regex
            return (ParseError.BADREQ, None, None, None, None)

        # if a header name is already in the "headers" dictionary something is probably wrong
        if name + b":" in headers:
            logging.error("(parse_request) Duplicate HTTP header")
            return (ParseError.BADREQ, None, None, None, None)

        # add "<header name>:", "<header value" to 'headers' dictionary
        # headers[name + b":"] = value.strip()
        headers[name] = value.strip()

    # error_type gets set to ParseError.NOTIMPL if request is valid but something other than GET
    if error_type:
        return (error_type, None, None, None, None)

    return None, host, port, path, headers


notimplreq = (ParseError.NOTIMPL, None, None, None, None)
badreq = (ParseError.BADREQ, None, None, None, None)

requests = [
    # Just a kick the tires test
    (
        b"GET http://www.google.com/ HTTP/1.0\r\n\r\n",
        (None, b"www.google.com", 80, b"/", {}),
    ),
    # 102.2) Test handling of malformed request lines [0.5 points]
    (b"HEAD http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\n\r\n", notimplreq),
    (b"POST http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\n\r\n", notimplreq),
    (b"GIBBERISH http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\n\r\n", badreq),
    # 102.3) Test handling of malformed header lines [0.5 points]
    (
        b"GET http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\nthis is not a header\r\n\r\n",
        badreq,
    ),
    (
        b"GET http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\nConnection : close\r\n\r\n",
        badreq,
    ),
    (
        b"GET http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\nConnection:close\r\n\r\n",
        badreq,
    ),
    (
        b"GET http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:50.0) Firefox/50.0\r\ngibberish\r\n\r\n",
        badreq,
    ),
    # 102.4) Test handling of malformed URIs [0.5 points]
    (b"GET www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\n\r\n", badreq),
    (b"GET http://www.flux.utah.edu HTTP/1.0\r\n\r\n", badreq),
    (b"GET /cs4480/simple.html HTTP/1.0\r\n\r\n", badreq),
    (b"GET gibberish HTTP/1.0\r\n\r\n", badreq),
    # 102.5) Test handling of wrong HTTP versions
    (b"GET http://www.flux.utah.edu/cs4480/simple.html HTTP/1.1\r\n\r\n", badreq),
    (b"GET http://www.flux.utah.edu/cs4480/simple.html\r\n\r\n", badreq),
    (b"GET http://www.flux.utah.edu/cs4480/simple.html 1.0\r\n\r\n", badreq),
    (b"GET http://www.flux.utah.edu/cs4480/simple.html gibberish\r\n\r\n", badreq),
    # 103.5) Requests should include the specified headers [0.5 points]
    (
        b"GET http://localhost:8080/simple.html HTTP/1.0\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:50.0) Firefox/50.0\r\n\r\n",
        (
            None,
            b"localhost",
            8080,
            b"/simple.html",
            {
                b"Connection": b"close",
                b"User-Agent": b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:50.0) Firefox/50.0",
            },
        ),
    ),
]

for request, expected in requests:
    print(f"Testing {request}")
    parsed = parse_request(request)
    assert parsed == expected, f"{request} yielded {parsed} instead of {expected}"
print("All tests passed!")


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
