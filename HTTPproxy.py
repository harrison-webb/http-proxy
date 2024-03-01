"""
Harrison Webb
Computer Networks Spring 2024
University of Utah

Big picture:
1. proxy starts up and begins listening for connections
2. Establishes connection with client
3. Proxy reads data from client and ensures client has sent a properly formatted HTTP GET request
    a. If client has sent a request containing proxy command, process that and send 200 OK back to client (or 400 if bad command)
4. If blocklist or cache is enabled, check GET request against the relevant one
    a. If request is cached, check with origin that object is current, update if not, and send object back to client
    b. If request is in blocklist, send 403 FORBIDDEN response back to client
4. Proxy formats client request and sends it on to the origin server
5. Proxy waits for response from origin, sends the response back to client, then closes connections
"""

import logging
import re
import signal
import sys
import threading
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from optparse import OptionParser
from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, socket
from typing import Optional
from urllib.parse import urlparse


def ctrl_c_pressed(signal, frame):
    """Signal handler for pressing ctrl-c"""
    sys.exit(0)


logging.basicConfig(level=logging.DEBUG)


@dataclass
class CacheObject:
    """Used as the value of a url key in the cache. Contains a response corresponding to a url and the response's Last-Modified date"""

    response: bytes
    date: bytes


#### Global Variables ####
http_methods = {b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS"}
ok_response = b"HTTP/1.0 200 OK\r\n\r\n"

# used when client sends bad proxy command
bad_req_response = b"HTTP/1.0 400 Bad Request\r\n\r\n"

# used when client attempts to access blocked host
forbidden_response = b"HTTP/1.0 403 Forbidden\r\n\r\n"

# Proxy cache. Cache keys are `<hostname><path>` and values are CacheObject (response + date)
cache: dict[bytes, CacheObject] = {}

# Blocklist just uses a set to store phrases to block
blocklist: set[bytes] = set()

# Global flags to toggle cache and blocklist
cache_enabled = False
blocklist_enabled = False


class ParseError(Enum):
    """Request parsing"""

    NOTIMPL = 1
    BADREQ = 2


class ParsedRequest:
    """Parsed (deconstructed) HTTP request"""

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
        """Detect if the request is valid or not. A valid request has None for the error field"""
        if self.error == ParseError.BADREQ or self.error == ParseError.NOTIMPL:
            return False
        else:
            return True

    def error_response(self) -> bytes:
        """Return an error response bytestring corresponding to the type of error a request has

        Returns:
            bytes: "400 Bad Request" or "501 Not Implemented" HTTP response bytestrings
        """
        if self.error == ParseError.NOTIMPL:
            return b"HTTP/1.0 501 Not Implemented\r\n"
        elif self.error == ParseError.BADREQ:
            return b"HTTP/1.0 400 Bad Request\r\n"
        else:
            logging.error(
                "line 97: error_response called on ParsedRequest object with no error"
            )
            return b""

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

        other_headers = b""
        if self.headers:
            other_headers = b"\r\n".join(
                [key + b": " + value for key, value in self.headers.items()]
            )

        result = b"".join([result, other_headers, b"\r\n\r\n"])
        return result

    def conditional_get_string(self, cache_obj: CacheObject) -> bytes:
        """Given a valid request and the stored Last-Modified date for the request, generate a conditional get request

        Args:
            cache_obj (CacheObject): Object containing valid HTTP request and it's Last-Modified date as bytestrings

        Returns:
            bytes: Conditional get request
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
            (str(self.port)).encode(),
            b"\r\n",
            b"If-Modified-Since: ",
            cache_obj.date,
            b"\r\n",
            b"Connection: close\r\n",
            b"\r\n\r\n",
        ]
        conditional_get_req = b"".join(tokens)
        return conditional_get_req


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
        # Pattern to match valid header.
        # A valid header is "<name>: <value>",there is no whitespace before the colon, and one space after it
        # <value> is allowed to contain a colon, as long as it has text on both sides of it
        if re.search(r"^[^:]+[^\s]: (([^:]+)|(.*\S:\S.*))$".encode(), line):
            name, value = line.split(b":", 1)
        else:
            # invalid header if it does not match the regex
            return ParsedRequest(ParseError.BADREQ, None, None, None, None)

        # Omit "Connection: <value>" header. This gets added manually in ParsedRequest.to_request_string()
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


def get_last_modified_date_from_response(response: bytes) -> bytes:
    """Extract the 'Last-Modified' header of a response

    Args:
        response (bytes): Entire response sent from origin server

    Returns:
        bytes: Last-Modified header of response
    """
    response_items = response.split(b"\r\n")
    for item in response_items:
        if item.startswith(b"Last-Modified:"):
            date_string = item.split(b" ", 1)[1]
            return date_string

    # if no date header is found just put the current date/time
    current_time = datetime.utcnow()
    # format like 'Sat, 22 Jan 2022 23:19:27 GMT'
    formatted_current_time = current_time.strftime("%a, %d %b %Y %H:%M:%S GMT")
    return formatted_current_time.encode()


def handle_proxy_command(request: ParsedRequest) -> bytes:
    """Handles a request sent by the client that contains a command URL for the proxy (e.g. /proxy/cache/enable or /proxy/blacklist/flush)

    Args:
        request (ParsedRequest): ParsedRequest object containing the client's request

    Raises:
        ValueError: If the ParsedRequest object has no path this error is thrown (should never happen)

    Returns:
        bytes: "200 OK" HTTP response message, or "400 Bad Request" if client sends an invalid command URL
    """
    global cache_enabled
    global blocklist_enabled

    if request.path == None:
        raise ValueError("handle_proxy_command called on request with null path")
    assert request.path.startswith(b"/proxy")

    response = ok_response

    command = request.path
    match command:
        case b"/proxy/cache/enable":
            cache_enabled = True
        case b"/proxy/cache/disable":
            cache_enabled = False
        case b"/proxy/cache/flush":
            cache.clear()
        case b"/proxy/blocklist/enable":
            blocklist_enabled = True
        case b"/proxy/blocklist/disable":
            blocklist_enabled = False
        case b"/proxy/blocklist/flush":
            blocklist.clear()
        case _:
            if command.startswith(b"/proxy/blocklist/add/"):
                string_to_add = request.path.split(b"/", 4)[-1]
                blocklist.add(string_to_add)
            elif command.startswith(b"/proxy/blocklist/remove/"):
                string_to_remove = request.path.split(b"/", 4)[-1]
                if string_to_remove in blocklist:
                    blocklist.remove(string_to_remove)
                else:
                    response = bad_req_response
            else:
                logging.debug(
                    f"line 267 in handle_proxy_command: unhandled proxy command: {request.path}"
                )
                response = bad_req_response

    return response


def update_cache(response: bytes, url: bytes) -> bool:
    """Update the cache based on the origin's response for the specified url.

    - 200 OK -> cache gets updated with the new object and time sent in response. Return True.
    - 304 Not Modified -> cache is not modified. Return True.
    - Anything else (e.g. 401, 404, etc) -> url is removed from cache. Return False.

    Args:
        response (bytes): Response sent back from the origin server
        url (bytes): URL being requested by the client

    Returns:
        bool: True if the server sends a successful response (200 or 304), False if it sends an error response (e.g 404)
    """
    response_items = response.split(b"\r\n")

    # extract the status code from the response
    http_status = response_items[0].split()[1]

    if http_status == b"200":
        # 200 code from conditional get means object is updated, so update the cache with it
        cache[url] = CacheObject(
            response, get_last_modified_date_from_response(response)
        )
        return True
    elif http_status == b"304":
        # 304 Not Modified means no need to change cache
        return True
    else:
        # anything other than 200 or 304 is bad -> invalidate cached object
        if url in cache:
            cache.pop(url)
        return False


def handle_request_with_cache(parsed_request: ParsedRequest, client_skt: socket):
    """Process a request from a client when the proxy cache is enabled

    Overview:
    - check if requested object is in the cache
    - if not, carry out request like usual
    - if so, verify object is up to date by issuing conditional GET to origin
    - if origin replies 304, then object is unmodified and things are good to go
    - if origin replies 200, object has been modified -> update object and date in cache
    - respond to client with up to date object from cache

    Args:
        parsed_request (ParsedRequest): Client's request
        client_skt (socket): Client socket

    """
    if parsed_request.hostname is None or parsed_request.path is None:
        raise ValueError("handle_request_with_cache: invalid request")

    hostname = parsed_request.hostname
    port_bytes = str(parsed_request.port).encode()
    path = parsed_request.path

    url = b"".join([hostname, b":", port_bytes, path])

    if url in cache:
        # site has been cached, send conditional GET to origin to check if object is up to date
        with socket(AF_INET, SOCK_STREAM) as origin_skt:
            origin_skt.connect((parsed_request.hostname.decode(), parsed_request.port))
            origin_skt.sendall(parsed_request.conditional_get_string(cache[url]))

            # Get response from origin-- read until origin sends empty string, indicating end of stream
            origin_response = b""
            while True:
                temp = origin_skt.recv(4096)
                if temp == b"":
                    break
                origin_response += temp

            # Modify cache if necessary based on response
            response_successful = update_cache(origin_response, url)

            if response_successful:
                client_skt.sendall(cache[url].response)
            else:
                client_skt.sendall(origin_response)

            client_skt.close()
            origin_skt.close()

    else:
        # site has not been cached, carry out request per usual and store response in cache
        with socket(AF_INET, SOCK_STREAM) as origin_skt:
            origin_skt.connect((parsed_request.hostname.decode(), parsed_request.port))
            origin_skt.sendall(parsed_request.to_request_string())

            # Get response from origin-- read until origin sends empty string, indicating end of stream
            origin_response = b""
            while True:
                temp = origin_skt.recv(4096)
                if temp == b"":
                    break
                origin_response += temp

            response_successful = update_cache(origin_response, url)

            if response_successful:
                client_skt.sendall(cache[url].response)
            else:
                # if response is 401, 404, etc., don't consult cache and just send the response straight back to client
                client_skt.sendall(origin_response)

            client_skt.close()
            origin_skt.close()


def handle_request_with_blocklist(parsed_request: ParsedRequest, client_skt: socket):
    """Process a request from a client when the proxy blocklist is enabled

    Args:
        parsed_request (ParsedRequest): Client's request
        client_skt (socket): Client socket
    """
    host_string = b""
    if parsed_request.hostname:  # hostname must not be None
        host_string = b"".join(
            [parsed_request.hostname, b":", str(parsed_request.port).encode()]
        )
    else:
        raise ValueError("handle_request_with_blocklist: request hostname is None")

    for blocked in blocklist:
        # if host_string contains any string that is in the blocklist, send "403 Forbidden"
        if blocked in host_string:
            client_skt.sendall(forbidden_response)
            client_skt.close()
            return

    if cache_enabled:
        handle_request_with_cache(parsed_request, client_skt)
    else:
        handle_request_standard(parsed_request, client_skt)


def handle_request_standard(parsed_request: ParsedRequest, client_skt: socket):
    """Process a request from a client when the proxy blocklist and cache are DISABLED

    Overview:
    - connect to origin
    - forward client request to origin
    - recv origin's response
    - forward response back to client
    - close connections

    Args:
        parsed_request (ParsedRequest): Client's request
        client_skt (socket): Client socket
    """
    assert parsed_request.hostname is not None
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


def communicate_with_client(client_skt: socket, client_address):
    """Once connection is established with a client, revc message from them, forward message to origin server, then forward origin response back to client

    Args:
        client_skt (socket): Socket connecting client and proxy. Obtained from skt.accept()
        client_address (_type_): Client address. Unused here
    """
    # revc from client until termination sequence is sent
    client_request = b""
    while True:
        data = client_skt.recv(10)
        client_request += data
        if client_request.endswith(b"\r\n\r\n"):
            break

    # Parse HTTP request:
    parsed_request = parse_request(client_request)

    # if invalid just send straight back to the client and close the connection
    if not parsed_request.is_valid_request():
        client_skt.send(parsed_request.error_response())
        client_skt.close()
        return

    # Check if request is a cache or blocklist command:
    assert parsed_request.path is not None  # appease type checker
    if parsed_request.path.startswith(b"/proxy"):
        proxy_command_response = handle_proxy_command(parsed_request)
        client_skt.sendall(proxy_command_response)
        client_skt.close()  # TODO maybe keep this open?
        return

    # Handle request processing based on status of blocklist and cache:
    if blocklist_enabled:
        handle_request_with_blocklist(parsed_request, client_skt)
    elif cache_enabled:
        handle_request_with_cache(parsed_request, client_skt)
    else:
        handle_request_standard(parsed_request, client_skt)


#### START OF PROGRAM EXECUTION ####
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

        # handle connection on new thread
        client_thread = threading.Thread(
            target=communicate_with_client, args=(client_skt, client_address)
        )
        client_thread.start()
