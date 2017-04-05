# takes a packet as input, modifies its payload/header, and resends it

from scapy.all import *
import time

# takes in a packet from the main thread and modifies its seq num and timestamp
def modifyPacketHeader(packet, new_seq, new_ts):
	packet.sequence = new_seq
	packet.timestamp = new_ts

# replaces a packet's payload	
def modifyPacketPayload(packet, new_payload):
	packet[Raw].load = new_payload

# Sends the packet to the address. Timing is left up to the main thread
def sendPacket(packet):
	send(packet)

if __name__ == '__main__':
	# create a dummy packet
	rtp = RTP(payload_type=26, sequence=5, timestamp=17)
	ip = IP(src="192.168.1.101", dst="10.0.0.2")
	udp = UDP(sport=1001, dport=1002)
	raw = "hello, this is raw data."
	test_packet = ip/udp/rtp/raw
	
	print "Original packet:"
	print test_packet.summary()
	print test_packet.show()
	print "\n\n\n"
	
	# modify the packet's header
	modifyPacketHeader(test_packet, 8, 21)
	
	print "Packet with modified header:"
	print test_packet.summary()
	print test_packet.show()
	print "\n\n\n"
	
	# modify the packet's raw payload
	modifyPacketPayload(test_packet, "This is a new payload.")
	
	print "Packet with modified raw payload:"
	print test_packet.summary()
	print test_packet.show()
	print "\n\n\n"
	
	print test_packet.getlayer(RTP).load
	
	while 1:
		time.sleep(1)
		sendPacket(test_packet)
