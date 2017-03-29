import sys
from timeit import default_timer as timer
from scapy.all import *

printLine = "====================\n"

print printLine
print "Beginning Sniff\n"
print printLine

start = timer()

while True:
	packetList = sniff(filter="udp and len>1355", count=1)
	packet = packetList[0]
	if packet[UDP].len == 1336:
		break

#TODO: Build RTP Layer
rtpLayer = RTP()
raw = packet[Raw].load

currByte = ord(raw[0])

ver = currByte >> 6
rtpLayer.version = ver

pad = currByte >> 5
pad = pad&1
rtpLayer.padding = pad

ext = currByte >> 4
ext = ext&1
rptLayer = ext

cc = currByte&15
rtpLayer.numsync = cc

currByte = ord(raw[1])

mark = currByte >> 7
rtpLayer.marker = mark

payloadType = currByte&127
rtpLayer.payload = payloadType

hiByte = raw[2]
loByte = raw[3]

hiByte = hiByte << 8
seq = hiByte + loByte
rtpLayer.sequence = seq

#TODO: Rebuild packet with RTP layer

#TODO: send packet to injector
