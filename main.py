import sys, os
import argparse
from scapy.all import *
from scapy.all import IP, TCP
import socket
from scapy_ssl_tls.ssl_tls import *
import threading
from functools import partial
import requests
from multiprocessing import Pool
import multiprocessing

load_layer("tls")

MY_IP = '128.12.16.127'
MSS_SIZE = 64

parser = argparse.ArgumentParser()
parser.add_argument("--ip", type=str)
parser.add_argument("--url", type=str)
parser.add_argument("--sniff", action="store_true")
parser.add_argument("--numwebsite", type=int)
parser.add_argument("--start", type=int)

args = parser.parse_args()

if args.url:
    TARGET_IP = socket.gethostbyname(args.url)
else:
    TARGET_IP = args.ip

def listen_all(self, pkt):
    # print "---------------------------------------------------"
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
    else:
        return

    if TCP in pkt:
        tcp_sport = pkt[TCP].sport
        tcp_dport = pkt[TCP].dport
    else:
        return

    seq_no = pkt[TCP].seq
    ack_no = pkt[TCP].ack

    '''
    if ip_src == MY_IP or ip_dst == MY_IP:
        print("%s:%s --> %s:%s" % (ip_src, tcp_sport, ip_dst, tcp_dport))
        print("   seq : %d, ack : %d, size : %d" % (seq_no, ack_no, len(pkt)))
    '''

    # Received another packet after last ACK to retrasmitted ACK.
    if self.do_reset:
        # print "Sent RESET"
        ip = IP(ttl=255)
        ip.src = MY_IP
        ip.dst = ip_src

        max_seq_no = max(self.received_seq_no) + 1
        RST = TCP(
            sport=self.port_num,
            dport=443,
            flags='R',
            seq=self.last_ack_no,
            ack=max_seq_no)
        send(ip / RST, verbose=False)

        # print self.received_seq_no
        self.iw = max(self.received_seq_no) - min(
            self.received_seq_no) + self.last_packet_len
        return

    # Start tracking after client hello is sent.
    if ip_dst == MY_IP and self.client_hello_sent:
        ip_total_len = pkt[IP].len
        ip_header_len = pkt[IP].ihl * 32 / 8
        tcp_header_len = pkt[TCP].dataofs * 32 / 8
        tcp_seg_len = ip_total_len - ip_header_len - tcp_header_len

        tcp_payload_size = tcp_seg_len
        # print "Payload size : ", tcp_payload_size

        if tcp_payload_size == 0:
            return

        if seq_no not in self.received_seq_no:
            self.received_seq_no.add(seq_no)
            self.last_ack_no = ack_no
            self.last_packet_len = tcp_payload_size

        else:
            # print "Last ack no : ", self.last_ack_no, ack_no
            if self.last_ack_no != ack_no:
                self.last_ack_no = ack_no
            else:
                # Retransmitted ACK is received.
                # print ">>>>>>>>>>> ACK to retrasmitted ACK sent <<<<<<<<<<<<"
                ip = IP(ttl=255)
                ip.src = MY_IP
                ip.dst = ip_src

                max_seq_no = max(self.received_seq_no) + 1
                # print "Retrasmit ACK : ", max_seq_no, self.last_ack_no
                ACK = TCP(
                    sport=self.port_num,
                    dport=443,
                    flags='A',
                    seq=self.last_ack_no,
                    ack=max_seq_no,
                    window=65535,
                    options=[("MSS", MSS_SIZE), ('WScale', 10)])

                send(ip / ACK, verbose=False)
                self.do_reset = True


class Sniffer(threading.Thread):
    def __init__(self, port_num, url):
        threading.Thread.__init__(self)

        self.seq_no = 0
        self.port_num = port_num
        self.url = url
        self.client_hello_sent = False
        self.received_seq_no = set()

        self.last_ack_no = 0
        self.last_packet_len = 0
        self.do_reset = False
        self.iw = 0

    def run(self):
        print "Start sniffing on port " + str(self.port_num) + " :: " + self.url
        sniff(
            iface='enp33s0',
            prn=partial(listen_all, self),
            filter='tcp port ' + str(self.port_num),
            timeout=5)


def three_way_handshake(ip_dst, sniffer, port_num):
    ip = IP(ttl=255)
    ip.src = MY_IP
    ip.dst = ip_dst

    tcp = TCP(
        sport=port_num,
        dport=443,
        flags='S',
        seq=1000,
        window=65535,
        options=[("MSS", MSS_SIZE), ('WScale', 10)])

    SYNACK = sr1(ip / tcp, verbose=False, timeout=2)
    if not SYNACK:
        return

    tls = TLSRecord() / TLSHandshakes(handshakes=[
        TLSHandshake() / TLSClientHello(
            compression_methods=list(range(0xff))[::-1],
            cipher_suites=list(range(0xff)))
    ])

    tls_raw = str(tls)
    ptr = 0
    current_ack = SYNACK.ack
    while ptr < len(tls_raw):
        ACK = TCP(
            sport=port_num,
            dport=443,
            flags='A',
            seq=current_ack,
            ack=SYNACK.seq + 1,
            window=65535,
            options=[("MSS", MSS_SIZE), ('WScale', 10)])

        tls_frag = tls_raw[ptr:ptr + MSS_SIZE]
        send(ip / ACK / tls_frag, verbose=False)
        ptr += MSS_SIZE
        current_ack += len(tls_frag)

    sniffer.client_hello_sent = True

class ICWEstimate():
    def __init__ (self, url, port_num):
        self.url = url
        self.port_num = port_num

    def run_icw_estimate(self):
        sniffing = Sniffer(self.port_num, self.url)
        sniffing.start()

        website_ip = socket.gethostbyname(self.url)
        three_way_handshake(website_ip, sniffing, self.port_num)

        sniffing.join()
        return sniffing.iw

def do_icw(url):
    current = multiprocessing.current_process()
    worker_id = int(current._identity[0])

    estimate = ICWEstimate(url, 55554 + worker_id)
    icw = estimate.run_icw_estimate()
    print "Estimiate : " + url + " :: " + str(icw)
    return icw

if __name__ == "__main__":
    # Read the top 5000 websites.
    fp = open("top.txt")
    lines = fp.read().split("\r\n")
    fp.close()

    url_list = []
    for line in lines:
        url = line[line.find('\t') + 1:]
        if url == "Hidden profile":
            continue

        url_list.append(url)
        if len(url_list) >= 4550:
            break

    start = 0
    if args.start:
        start = args.start

    url_list = url_list[start:start+args.numwebsite]
    print url_list
    p = Pool(5)
    icw_result = p.map(do_icw, url_list)

    url_to_icw = {}
    for i in range(len(url_list)):
        url_to_icw[url_list[i]] = icw_result[i]

    print url_to_icw
