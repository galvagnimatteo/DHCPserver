from __future__ import print_function
from scapy.all import *
from DHCPpacket import DHCPpacket
import socket, time


def send(packet):

    clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    time.sleep(10)
    clientSock.sendto(packet, ('255.255.255.255', 67))


def handle_packet(packet):

    bytes = raw(packet)
    bytes = bytes[42:]

    received_packet = DHCPpacket(bytes)
    packet_to_send = received_packet

    if received_packet.get_type() == 1:

        print("-----------------------DHCP DISCOVER------------------------")

        received_packet.to_string()

        packet_to_send.yiaddr = received_packet.option_requestedAddress
        packet_to_send.siaddr = [192, 168, 1, 9]
        packet_to_send.op = 2

        packet_to_send.option_leaseTime = 3600
        packet_to_send.option_messageType = 2
        packet_to_send.option_subnetMask = [255, 255, 255, 0]
        packet_to_send.option_broadcastAddress = [192, 168, 1, 255]
        packet_to_send.option_requestedAddress = None

        print("--------------------CREATED DHCP OFFER----------------------")

        DHCPpacket(packet_to_send.to_bytes()).to_string()

        send(packet_to_send.to_bytes())


    elif received_packet.get_type() == 3:

        print("-----------------------DHCP REQUEST-------------------------")
        received_packet.to_string()




if __name__ == "__main__":

    sniff(filter="udp and (port 67 or port 68)", prn=handle_packet) # TODO: port 67
