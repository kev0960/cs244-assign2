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
import csv

load_layer("tls")

MY_IP = '128.12.16.127'
MSS_SIZE = 64

parser = argparse.ArgumentParser()
parser.add_argument("--numwebsite", type=int)
parser.add_argument("--start", type=int)
parser.add_argument("--numport", type=int)
parser.add_argument("--url", type=str)

args = parser.parse_args()

NUM_OPEN_PORTS = args.numport
if not NUM_OPEN_PORTS:
    NUM_OPEN_PORTS = 5


def listen_all(self, pkt):
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

    # Received another packet after last ACK to retrasmitted ACK.
    if self.do_reset:
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

        if tcp_payload_size == 0:
            # If this is RST
            if pkt[TCP].flags & 0x04:
                self.state = "RSTRECV"
            elif pkt[TCP].flags & 0x01:
                self.state = "FINRECV"
            return

        if tcp_payload_size > MSS_SIZE:
            self.state = "MSSLARGE"

        if seq_no not in self.received_seq_no:
            self.received_seq_no.add(seq_no)
            self.last_ack_no = ack_no
            self.last_packet_len = tcp_payload_size

        else:
            if self.last_ack_no != ack_no:
                self.last_ack_no = ack_no
            else:
                # Retransmitted ACK is received.
                ip = IP(ttl=255)
                ip.src = MY_IP
                ip.dst = ip_src

                max_seq_no = max(self.received_seq_no) + 1
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
        self.state = "SUCCESS"

    def run(self):
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
        return "NOSYNACK"

    tls = TLSRecord() / TLSHandshakes(handshakes=[
        TLSHandshake() / TLSClientHello(
            compression_methods=list(range(0xff))[::-1],
            cipher_suites=list(range(0xff)))
    ])

    tls_raw = str(tls)
    ptr = 0
    current_ack = SYNACK.ack

    if SYNACK.seq is None:
        return "SYNACKERROR"

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

    return "SUCCESS"


class ICWEstimate():
    def __init__(self, url, port_num):
        self.url = url
        self.port_num = port_num

    def run_icw_estimate(self):
        sniffing = Sniffer(self.port_num, self.url)
        sniffing.start()

        try:
            website_ip = socket.gethostbyname(self.url)
        except:
            return ("URLNOEXIST", 0)

        sniffing.state = three_way_handshake(website_ip, sniffing,
                                             self.port_num)
        sniffing.join()
        return (sniffing.state, sniffing.iw)


def do_icw(url):
    current = multiprocessing.current_process()
    worker_id = int(current._identity[0])

    worker_id = worker_id % NUM_OPEN_PORTS
    print "Start : " + url
    estimate = ICWEstimate(url, 55555 + worker_id)
    state, icw = estimate.run_icw_estimate()
    print "Estimiate : " + url + " :: " + str(icw) + "[" + state + "]"
    return (state, icw)


def classify(url_to_icw):
    table_2_dict = {}
    table_3_dict = {}

    for url in url_to_icw:
        result = url_to_icw[url]

        # First count the number of success
        cnt = 0
        success_to_cnt = {}
        for state, icw in result:
            if state == "SUCCESS":
                success_to_cnt[icw] = success_to_cnt.get(icw, 0) + 1
                cnt += 1
        if cnt >= 3:
            icw = next(iter(success_to_cnt))
            if success_to_cnt[icw] != cnt:
                table_2_dict[url] = 2  # Category 2
            else:
                table_2_dict[url] = 1  # Category 1
                table_3_dict[url] = icw
        elif 1 <= cnt <= 2:
            icw = next(iter(success_to_cnt))
            if success_to_cnt[icw] != cnt:
                table_2_dict[url] = 4  # Category 4
            else:
                table_2_dict[url] = 3  # Category 3
        else:
            table_2_dict[url] = 5  # Category 5

    print table_3_dict
    print table_2_dict

    table_2 = [0, 0, 0, 0, 0]
    for url in table_2_dict:
        table_2[table_2_dict[url] - 1] += 1

    with open("table_2.csv", "wb") as csvfile:
        writer = csv.writer(csvfile, delimiter=",")
        for i in range(5):
            writer.writerow([i, table_2[i]])

    with open("table_3.csv", "wb") as csvfile:
        writer = csv.writer(csvfile, delimiter=",")
        for url in table_3_dict:
            writer.writerow([url, table_3_dict[url]])

    with open("table_4.csv", "wb") as csvfile:
        writer = csv.writer(csvfile, delimiter=",")
        for url in url_to_icw:
            writer.writerow([url] + url_to_icw[url])


if __name__ == "__main__":
    if args.url:
        p = Pool(NUM_OPEN_PORTS)
        url_list = [args.url]
        icw_result = p.map(do_icw, url_list)
        print icw_result
        exit()

    # Read the top 5000 websites.
    fp = open("top.txt")
    lines = fp.read().split("\r\n")
    fp.close()

    url_list = []
    url = ""
    for line in lines:
        url = line[line.find('\t') + 1:]
        if url == "Hidden profile":
            continue

        url_list.append(url)
        if len(url_list) >= 5000:
            break

    start = 0
    num_website_to_handle = 1
    if args.start:
        start = args.start
    if args.numwebsite:
        num_website_to_handle = args.numwebsite

    url_list = url_list[start:start + num_website_to_handle]
    print url_list
    url_to_icw = {}

    for _ in range(5):
        p = Pool(NUM_OPEN_PORTS)
        icw_result = p.map(do_icw, url_list)

        for i in range(len(url_list)):
            if url_list[i] in url_to_icw:
                url_to_icw[url_list[i]].append(icw_result[i])
            else:
                url_to_icw[url_list[i]] = [icw_result[i]]

    print url_to_icw
    classify(url_to_icw)
