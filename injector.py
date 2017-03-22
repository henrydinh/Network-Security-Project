# takes a packet as input, modifies its payload/header, and resends it

from scapy.all import *

# takes in a packet from the main thread and modifies its seq num and timestamp
def modifyPacket(packet, new_seq, new_ts):
	packet.sequence = new_seq
	packet.timestamp = new_ts

# Sends the packet to the address. Timing is left up to the main thread
def sendPacket(packet, address):
	None

if __name__ == '__main__':
	# create a dummy packet
	rtp = RTP(payload_type=17, sequence=5, timestamp=17)
	ip = IP(src="192.168.1.114", dst="192.168.1.25")
	udp = UDP(sport=1001, dport=1002)
	test_packet = rtp/udp/ip
	
	print "Original packet:"
	print test_packet.show()
	print "\n\n\n"
	
	# modify the packet
	modifyPacket(test_packet, 8, 21)
	
	print "Modified packet:"
	print test_packet.show()
