#Andromeda - Flag Capturing System 
#Copyright (c) Jannis Kirschner
#Licence 2017

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
	#Define search patterns here
	regexp = re.compile(r'YOUR REGEX')
	if regexp.search(packet):
		trigger()

	else:
		false()

def trigger():
	#Define trigger actions here
	print cache

def false():
	#Define action when no hit
	print ""

dump = sniff(iface="YOUR INTERFACE",prn=packet_callback)
