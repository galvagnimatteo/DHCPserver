import socket
import os, time


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
sock.sendto(bytes("TEST", "utf-8"), ("192.168.1.1", 67))
