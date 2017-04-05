import sys
from scapy.all import *
import threading
import file listener
import file injector

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
