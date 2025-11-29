from scapy.all import *

packet = IP(dst="127.0.0.1") / UDP(sport=12345, dport=123) / Raw("\x17\x00\x03\x2a" + "\x00" * 4)
send(packet, count=5)
