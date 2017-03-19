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
    between client and server. It is a UDP protocol that is run on port 123.

    In an NTP reflection attack, the attacker sends a crafted packet
    which requests a large amount of date send to the host.
    In this case, the attackers are taking advantage of the monlist command.
    Monlist is a remote command in older versions of NTP that sends the
    requester a list of the last 600 hosts who have connected to that server.
    For attackers the monlist query is a great reconnaissance tool.
    For a localized NTP server it can help to build a network profile.
    '''

    def monlist_scan(self, target):
        '''Simulate the monlist command and return `results`, a boolean
        indicating whether or not an answer was received.
        '''
        data = "\x17\x00\x03\x2a" + "\x00" * 4

        ip = IP(dst=target)

        udp = UDP(sport=random.randint(49152, 65536), dport=123)

        a = Raw(load=data)

        # A layer is a subclass of the Packet class.
        # All the logic behind layer manipulation is held by the Packet class
        # and will be inherited. A simple layer is compounded by a
        # list of fields that will be either concatenated when assembling the
        # layer or dissected one by one when disassembling a string.
        # Assemble a packet comprised of the layers IP, UDP and Raw
        # (in that order).
        pck = ip/udp/a

        # number of attempts
        retries = 0

        results = None

        while (retries < 3):

            # The sr() function is for  sending packets and receiving answers.
            # The function returns a couple of packet and answers, and the
            # unanswered packets. The function sr1() is a variant that only
            # return one packet that answered the packet (or the packet set)
            # sent. Send the single SYN packet `pck` to `target`, the given
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
