from __future__ import print_function
from scapy.all import *
from DHCPpacket import DHCPpacket
import socket, netifaces, time


def send(packet):

    clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientSock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    clientSock.sendto(packet, ('192.168.69.255', 68)) #broadcast


def get_local_ip(interface):

    return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']


def get_subnet_mask(interface):

    return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']


def get_broadcast_address(interface):

    return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['broadcast']


def to_list(ip):

    ip = ip.split(".")
    return [int(i) for i in ip]


def get_free_ip():

    return [192,168,1,100]


def handle_packet(packet):

    bytes = raw(packet)
    bytes = bytes[42:]

    received_packet = DHCPpacket(bytes)
    packet_to_send = received_packet

    if received_packet.get_type() == 1:

        print("-----------------------DHCP DISCOVER------------------------")

        received_packet.to_string()

        #se non e' presente l'opzione con l'ip richiesto ne fornisco uno
        packet_to_send.yiaddr = get_free_ip() #TODO: get free ip

        packet_to_send.siaddr = to_list(local_ip) #server address, getMyIp
        packet_to_send.op = 2

        packet_to_send.option_leaseTime = 3600
        packet_to_send.option_messageType = 2
        packet_to_send.option_subnetMask = to_list(subnet_mask) #get this subnet mask
        packet_to_send.option_broadcastAddress = to_list(broadcast_address) #get broadcast address
        packet_to_send.option_requestedAddress = None

        print("--------------------CREATED DHCP OFFER----------------------")

        DHCPpacket(packet_to_send.to_bytes()).to_string()

        send(packet_to_send.to_bytes())


    elif received_packet.get_type() == 3:

        print("------------------------DHCP REQUEST------------------------")

        received_packet.to_string()

        packet_to_send.siaddr = to_list(local_ip) #server address, getMyIp
        packet_to_send.op = 2

        packet_to_send.option_leaseTime = 3600
        packet_to_send.option_messageType = 5
        packet_to_send.option_subnetMask = to_list(subnet_mask) #get this subnet mask
        packet_to_send.option_broadcastAddress = to_list(broadcast_address) #get broadcast address
        packet_to_send.option_requestedAddress = None

        print("---------------------CREATED DHCP ACK-----------------------")

        DHCPpacket(packet_to_send.to_bytes()).to_string()

        send(packet_to_send.to_bytes())



if __name__ == "__main__":

    interface = "eno1"

    local_ip = get_local_ip(interface)
    subnet_mask = get_subnet_mask(interface)
    broadcast_address = get_broadcast_address(interface)

    print("\nINTERFACE", interface)
    print("\nIP address:", local_ip)
    print("Subnet mask:", subnet_mask)
    print("Broadcast address:", broadcast_address)

    print("\n**************************************************************************************\n")

    sniff(filter="udp and port 67", prn=handle_packet)
