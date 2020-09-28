
# expects all input to be utf-8 strings
def build_response(headers, payload):
    res = "HTTP/1.1 200 OK\r\n"

    if len(payload):
        headers["Content-Length"] = len(payload)        
    
    for key in headers:
        res += str(key)
        res += ": "
        res += str(headers[key])
        res += "\r\n"
    
    res += "\r\n"
    res += payload

    return res.encode("utf-8")


headers = {
    "Content-Type": "application/json",
    "Connection": "Closed"
}

body = "Constrution in progress"

http_req = build_response(headers, body)

print(http_req)
print("---")
print(http_req.decode("utf-8"))