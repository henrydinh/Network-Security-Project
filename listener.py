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

hiByte = ord(raw[2])
loByte = ord(raw[3])

hiByte = hiByte << 8
seq = hiByte + loByte
rtpLayer.sequence = seq

hiByte1 = ord(raw[4])
hiByte2 = ord(raw[5])
loByte1 = ord(raw[6])
loByte2 = ord(raw[7])

hiByte1 = hiByte1 << 24
hiByte2 = hiByte2 << 16
loByte1 = loByte1 << 8
time = hiByte1 + hiByte2 + loByte1 + loByte2
rtpLayer.timestamp = time

hiByte1 = ord(raw[8])
hiByte2 = ord(raw[9])
loByte1 = ord(raw[10])
loByte2 = ord(raw[11])

hiByte1 = hiByte1 << 24
hiByte2 = hiByte2 << 16
loByte1 = loByte1 << 8
ssrc = hiByte1 + hiByte2 + loByte1 + loByte2
rtpLayer.sourcesync = ssrc

hiByte1 = ord(raw[12])
hiByte2 = ord(raw[13])
loByte1 = ord(raw[14])
loByte2 = ord(raw[15])

hiByte1 = hiByte1 << 24
hiByte2 = hiByte2 << 16
loByte1 = loByte1 << 8
sync = hiByte1 + hiByte2 + loByte1 + loByte2
rtpLayer.sync = sync

print rtpLayer

#TODO: Rebuild packet with RTP layer

#TODO: send packet to injector
