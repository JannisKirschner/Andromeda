from scapy.all import *

cache = []
cachesize = 10

def packet_callback(packet):
	rawdump =  packet.sprintf("{Raw:%Raw.load%\n}")
	headerscan(rawdump)
	cache.append(rawdump)
	if len(cache) > cachesize:
		del cache[0]	

def headerscan(packet):
	regexp = re.compile(r'/^\w{31}=$/.')
	if regexp.search(packet):
		trigger()

	else:
		print ""

def trigger():
	print cache



dump = sniff(iface="eth0",prn=packet_callback)
