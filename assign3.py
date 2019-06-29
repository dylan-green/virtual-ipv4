import re
import sys
from array import array
import queue
import struct
import socket
import threading
import ipaddress


localhost = "localhost"
MAX_TRANSFER_SIZE = 1500


class IPv4Packet:
    def __init__(self, src_ip, dest_ip):
        self._version_ihl = b"\x45"  # version: 4, ihl: 5
        self._dspc_ecn = b"\x00"  # dspc: 0, ecn: 0
        self._total_length = struct.pack("!H", 20)  # 2-byte length
        self._identification = b"\x01\x01"  # TODO unique id?
        self._flags_offset = b"\x00\x00"  # flags: 0b000, offset: 0x000
        self._ttl = b"\x1e"  # ttl: 30 seconds
        self._protocol = b"\x00"  # protocol: 0
        self._checksum = b"\x00\x00"  # checksum: 0
        self._src_ip = self.build_ip(src_ip)  # src_ip: 4 bytes
        self._dest_ip = self.build_ip(dest_ip)  # dest_ip: 4 bytes
        self._data = b''

    def __str__(self):
        return str(self.get_raw_data())

    def get_raw_data(self):
        self.raw_data = (
            self._version_ihl
            + self._dspc_ecn
            + self._total_length
            + self._identification
            + self._flags_offset
            + self._ttl
            + self._protocol
            + self._checksum
            + self._src_ip
            + self._dest_ip
            + self._data
        )
        return self.raw_data

    def set_data(self, data):
        self._data = data
        length = int.from_bytes(self._total_length, byteorder="big") + len(data)
        self._total_length = struct.pack("!H", length)

    def build_ip(self, ip_string):
        ip = list(map(int, ip_string.split(".")))
        return struct.pack("!BBBB", ip[0], ip[1], ip[2], ip[3])


class Network:
    def __init__(self, net_ip, ll_addr, hosts=[], mtu=MAX_TRANSFER_SIZE):
        self._gateway = None  # gateway address
        self._gw_flag = False  # flag to indicate gateway. used for error reporting
        self._connection = None  # network connection, i.e. socket to transmit packet
        self._net_ip = net_ip  # ip of this network. defines subnet of self
        self._ll_addr = ll_addr  # link layer address of this network. i.e. port number
        self._hosts = hosts  # list of valid host addresses in this network
        self._arp_table = {}  # { 'ip_address' : 'port_num' }
        self._mtu = mtu  # max transfer size
        self.actions = {  # getter/setter methods to be dispatched
            "gw_get": self.gw_get,
            "gw_set": self.gw_set,
            "arp_get": self.arp_get,
            "arp_set": self.arp_set,
            "mtu_get": self.mtu_get,
            "mtu_set": self.mtu_set,
        }

    def set_connection(self, connection):
        self._connection = connection

    def lookup_link_address(self, ip_addr):
        link_address = None
        # TODO this is not safe need to check for error
        ip_address = ipaddress.ip_address(ip_addr)
        # IP is in subnet. Check for arp table entry
        if ip_address in self._hosts:
            link_address = self._arp_table.get(str(ip_address))
        # IP is not in subnet, but there is an arp entry
        elif self._arp_table.get(str(ip_address)) != None:
            link_address = self._arp_table.get(str(ip_address))
        # IP is not in subnet and there is no arp entry, but
        # there is a gateway address. Check arp table for gateway
        elif self._gateway != None:
            link_address = self._arp_table.get(self._gateway)
        else:
        # IP is outside the subnet and no default gateway has been
        # provided. Setting this flag will report a "No gateway found" error.
            self._gw_flag = True
        return link_address

    def packet_builder(self, ip_address, payload):
        message = " ".join(payload)
        data = re.sub('"', "", message).encode("utf-8")
        packet = IPv4Packet(src_ip=self._net_ip, dest_ip=str(ip_address))
        packet.set_data(data)
        return packet.get_raw_data()

    def transmit_message(self, message):
        try:
            ip_address = message[0]
            link_address = self.lookup_link_address(ip_address)
            assert not self._gw_flag, "No gateway found"
            assert link_address != None, "No ARP entry found"
            
            payload = message[1::]
            if len(payload) > self._mtu:
                # need to fragment the payload and send multiple packets
                pass
            else:
                packet = self.packet_builder(ip_address, payload)
                self._connection.sendto(packet, (localhost, int(link_address)))
        except AssertionError as error:
            # report the error but don't shut down the program
            print(error)

    ''' Getters and setters for the network attributes and adding entries
    to the ARP table. All are wrapped in a try/except to silently recover
    from any errors that occur due to invalid user input. '''
    def gw_get(self, args=None):
        print(self._gateway)

    def gw_set(self, args):
        try:
            gateway = ipaddress.IPv4Address(args[0])
            if gateway in self._hosts:
                self._gateway = str(gateway)
        except:
            pass

    def arp_get(self, args):
        try:
            print(self._arp_table.get(args[0]))
        except:
            pass

    def arp_set(self, args):
        try:
            ip_address = ipaddress.IPv4Address(args[0])
            ll_address = args[1]
            self._arp_table[str(ip_address)] = ll_address
        except:
            pass

    def mtu_get(self, args=None):
        print(self._mtu)

    def mtu_set(self, args):
        try:
            self._mtu = int(args[0])
        except:
            pass


''' Continuously recieve input on the bound socket
and pass the data to threadsafe input_q '''
def recv_thread(input_q, sock, mtu):
    while True:
        data = sock.recv(mtu)
        input_q.put(data)


''' Continuously poll the input_q for new messages to print
runs on a separate daemonic thread with threadsafe queue '''
def printer(input_q):
    while True:
        if not input_q.qsize() == 0:
            sys.stdout.write("\b\b")
            packet = input_q.get()
            protocol = packet[9]
            header = packet[0:19]
            src_ip = parse_ip_address(header)

            if protocol == 0:
                message = '"' + packet[20::].decode("utf-8") + '"'
                sys.stdout.write(f"Message received from {src_ip}: {message}\n")
            else:
                protocol = bytes([protocol]).hex()
                sys.stdout.write(
                    f"Message received from {src_ip} with protocol 0x{protocol}\n"
                )
            sys.stdout.write("> ")
            sys.stdout.flush()


def parse_ip_address(header):
    ip_address = header[12:16]
    return ".".join(list(map(str, ip_address)))

commands = ["gw_get", "gw_set", "arp_get", "arp_set", "mtu_get", "mtu_set"]

def main(args):
    ''' This is all network setup, getting the subnet from the CIDR
    ip address, hosts addresses in the network, the 'link layer addr'
    i.e. port number, and creating the network to use '''
    subnet = ipaddress.IPv4Network(args[1], False)
    net_ip = args[1].split("/")[0]
    port_num = int(args[2])
    hosts = list(subnet.hosts())
    network = Network(net_ip=net_ip, ll_addr=port_num, hosts=hosts)
    ''' This is all related to keeping things threadsafe. using a queue
    to transfer data from the receiving socket to the printer, both
    running on separate threads concurrently. both are daemon threads
    so that they're killable when the user exits the program. '''
    input_q = queue.Queue()
    ''' Create a UDP socket and bind to the provided 'link layer address'
    i.e. the port number. All transmissions are on localhost '''
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((localhost, port_num))
    network.set_connection(sock)
    # Start up threads for receiving network messages and the printer
    input_thread = threading.Thread(target=recv_thread, args=(input_q, sock,network._mtu,))
    printer_thread = threading.Thread(target=printer, args=(input_q,))
    printer_thread.daemon = True
    input_thread.daemon = True
    input_thread.start()
    printer_thread.start()

    while True:
        sys.stdout.write("> ")
        sys.stdout.flush()
        user_input = input().split(" ")
        if user_input[0] == "exit":
            sys.exit()
        elif user_input[0] == "msg":
            network.transmit_message(user_input[1::])
        else:
            args = user_input[2::]
            command = "_".join(user_input[0:2])
            if command in commands:
                # Dynamic dispatch of the network getters/setters
                network.actions[command](args)


if __name__ == "__main__":
    main(sys.argv)
