import logging
import sys
import time
from scapy.all import IP
from scapy.all import UDP
from scapy.all import Raw
from scapy.all import random
from scapy.all import sr1


logger = logging.getLogger("scapy.runtime")
logger.setLevel(49)


class NTPscan:
    '''Network Time Protocol (NTP) is used to synchronize the time
    between a client and server. It is a UDP protocol that is run on port 123.

    Monlist (the NTP Monitor List Scanner) is a remote command in older
    versions of NTP that allows administrators to query the server for traffic
    counts of connected clients. In response the the "get monlist" request, an
    unpatched NTP server sends the requester a list of the last 600 hosts
    who have connected to that server.
    '''

    def monlist_scan(self, target):
        '''Simulate the monlist command and return `results`, a boolean
        indicating whether or not an answer was received.

        If the `target` device is an NTP server that accepts the monlist
        request and that server is unpatched, it will return a lot of packets
        (each about 500 bytes) instead of returning one small packet.
        '''
        #TODO figure out the relevant exceptions to add and/or handle

        # `data` is the "get monlist" request
        data = "\x17\x00\x03\x2a" + "\x00" * 4

        # Create an IP layer for the packet, spoofing the target's address
        ip = IP(dst=target)

        # Create a UDP layer for the packet
        udp = UDP(sport=random.randint(49152, 65536), dport=123)

        # Create a Raw layer for the packet
        a = Raw(load=data)

        # A layer is a subclass of the Packet class.
        # All the logic behind layer manipulation is held by the Packet class
        # and will be inherited. A simple layer is compounded by a
        # list of fields that will be either concatenated when assembling the
        # layer or dissected one by one when disassembling a string.
        # Assemble the packet comprised of the layers IP, UDP and Raw.
        pck = ip/udp/a

        # number of attempts
        retries = 0

        results = None

        while (retries < 3):

            # The sr() function is for  sending packets and receiving answers.
            # The function returns a couple of packet and answers, and the
            # unanswered packets. The function sr1() is a variant that only
            # return one packet that answered the packet (or the packet set)
            # sent. Send the single packet `pck` to `target`, the given
            # IP address. Quit after receving a single response.
            rep = sr1(pck, verbose=0, timeout=5)

            if hasattr(rep, 'answers'):
                results = 1
                break

            elif not hasattr(rep, 'answers') and (retries < 3):
                retries += 1

            else:
                results = None
                break

        return results
