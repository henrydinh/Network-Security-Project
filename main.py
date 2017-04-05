import sys
from scapy.all import *
import threading

def listener():
        printLine = "===================="

        print printLine
        print "Beginning Capture Engine"
        print printLine

        start = timer()*1000

        while True:
                if (timer()*1000) >= start:
                        while True:
                                packetList = sniff(filter="udp and len>1355", count=1, timeout=.200)
                                if not packetList:
                                        #End the program
                                        return
                                packet = packetList[0]
                                if packet[UDP].len == 1336:
                                        break

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

                        #TODO: send packet to injector
                        print packet.show()

                        start = (timer()*1000) + 500
                        
        return


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
	
def injector(packet, new_sequence, new_timestamp):
	None
	

listener = threading.Thread(target = listener)
injector = threading.Thread(target = injector)

packetSem = BoundedSemaphore(value = 1)
termSem = BoundedSemaphore(value = 1)

packet = IP()
terminate = False

listener.run()
injector.run()

listener.join()
injector.join()

return
