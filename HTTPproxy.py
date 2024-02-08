"""
Harrison Webb
Computer Networks Spring 2024
University of Utah
"""

from socket import *
from urllib.parse import urlparse
from enum import Enum
from dataclasses import dataclass
import re
from typing import Optional
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
4. Proxy formats client request and sends it on to the origin server
5. Proxy waits for response from origin, sends the response back to client, then closes connections
"""


# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)


# Request parsing
class ParseError(Enum):
    NOTIMPL = 1
    BADREQ = 2


class ParsedRequest:
    def __init__(
        self,
        error: Optional[ParseError],
        hostname: Optional[bytes],
        port: Optional[int],
        path: Optional[bytes],
        headers: Optional[dict[bytes, bytes]],
    ):
        self.error = error
        self.hostname = hostname
        self.port = port
        self.path = path
        self.headers = headers

    def is_valid_request(self) -> bool:
        if self.error == ParseError.BADREQ or self.error == ParseError.NOTIMPL:
            return False
        else:
            return True

    def error_response(self):
        if self.error == ParseError.NOTIMPL:
            return b"HTTP/1.0 501 Not Implemented\r\n"
        elif self.error == ParseError.BADREQ:
            return b"HTTP/1.0 400 Bad Request\r\n"
        else:
            logging.error("error_response called on ParsedRequest object with no error")
            return None

    def to_request_string(self) -> bytes:
        """Format the ParsedRequest object into a string that can be sent as a valid GET request

        Example:
            GET /index.html HTTP/1.0
            Host: cs.utah.edu:8888
            Connection: close
            Accept-Language: en-us

        Returns:
            bytes: formatted request as a byte string
        """
        tokens = [
            b"GET ",
            self.path,
            b" ",
            b"HTTP/1.0",
            b"\r\n",
            b"Host: ",
            self.hostname,
            b":",
            str(self.port).encode(),
            b"\r\n",
            b"Connection: close\r\n",
        ]
        result = b"".join(tokens)
        other_headers = b"\r\n".join(
            [key + b": " + value for key, value in self.headers.items()]
        )
        result = b"".join([result, other_headers, b"\r\n\r\n"])
        return result


def parse_request(
    message: bytes,
) -> ParsedRequest:
    """Parse HTTP request text. Returns (ParseError, None, None, None, None) if the request is bad, or
    (None, hostname, port number, path, headers dictionary) if request is good

    Returns:
        ParsedRequest:
            class containing, TypeError, hostname, port number, path, and headers dictionary
    """
    host, port, path, headers = None, None, None, {}
    error_type = None

    # split message into first line and the rest of the headers
    request_line, headers_data = message.split(b"\r\n", 1)

    ### Request line validation:
    # Bad request if request line doesn't consist of "<method> <url> <http version>"
    if len(request_line.split(b" ")) != 3:
        return ParsedRequest(ParseError.BADREQ, None, None, None, None)
    method, url, http_version = request_line.split(b" ")

    # validate HTTP method
    if method not in http_methods:
        return ParsedRequest(ParseError.BADREQ, None, None, None, None)
    if method != b"GET":
        error_type = ParseError.NOTIMPL

    # validate url, set host, port, and path variables
    url_parse = urlparse(url)
    if url_parse.scheme != b"http" or url_parse.netloc == b"" or url_parse.path == b"":
        return ParsedRequest(ParseError.BADREQ, None, None, None, None)

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
        return ParsedRequest(ParseError.BADREQ, None, None, None, None)

    ### Parse + validate other headers:
    # split on newline to isolate each `<header name: <header value>`
    headers_arr = headers_data.split(b"\r\n")
    headers_arr = [x for x in headers_arr if x.strip()]  # remove whitespace lines
    for line in headers_arr:
        # Pattern to match valid header. A valid header is "<name>: <value>",
        #   there is no whitespace before the colon, and one space after it
        # <value> is allowed to contain a colon, as long as it has text on both sides of it
        if re.search(r"^[^:]+[^\s]: (([^:]+)|(.*\S:\S.*))$".encode(), line):
            name, value = line.split(b":", 1)
        else:
            # invalid header if it does not match the regex
            return ParsedRequest(ParseError.BADREQ, None, None, None, None)

        # Omit "Connection: <value>" header. I add this in manually in ParsedRequest.to_request_string()
        if name == b"Connection":
            continue

        # if a header name is already in the "headers" dictionary something is probably wrong
        if name + b":" in headers:
            logging.error("(parse_request) Duplicate HTTP header")
            return ParsedRequest(ParseError.BADREQ, None, None, None, None)

        # add "<header name>", "<header value" to 'headers' dictionary
        headers[name] = value.strip()

    # error_type gets set to ParseError.NOTIMPL if request is valid but something other than GET
    if error_type:
        return ParsedRequest(error_type, None, None, None, None)

    return ParsedRequest(None, host, port, path, headers)


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

# Set up socket to listen for incoming connections
with socket(AF_INET, SOCK_STREAM) as listen_skt:
    listen_skt.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    # bind socket to specified address + port and start it up
    listen_skt.bind((address, port))
    listen_skt.listen()

    while True:
        # establish connection with client
        client_skt, client_address = listen_skt.accept()

        # revc from client until termination sequence is sent
        client_request = b""
        while True:
            data = client_skt.recv(10)
            client_request += data
            if client_request.endswith(b"\r\n\r\n"):
                break

        # parse HTTP request
        logging.debug(client_request.decode())
        parsed_request = parse_request(client_request)

        # if invalid just send straight back to the client and close the connection
        if not parsed_request.is_valid_request():
            client_skt.send(parsed_request.error_response())
            client_skt.close()
            continue

        logging.debug(parsed_request.to_request_string().decode())
        # Connect to origin server
        with socket(AF_INET, SOCK_STREAM) as origin_skt:
            origin_skt.connect((parsed_request.hostname.decode(), parsed_request.port))

            # Forward client's request to origin
            origin_skt.sendall(parsed_request.to_request_string())

            # Get response from origin-- read until origin sends empty string, indicating end of stream
            origin_response = b""
            while True:
                temp = origin_skt.recv(4096)
                if temp == b"":
                    break
                origin_response += temp

            # Send response back to client
            client_skt.sendall(origin_response)
            client_skt.close()
            origin_skt.close()
