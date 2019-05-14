import array

class Option:

    def __init__(self, id, length, value):

        self.id = id
        self.length = length
        self.value = value


class DHCPpacket:

    def __init__(self, bytes):

        self.op = bytes[0]
        self.htype = bytes[1]
        self.hlen = bytes[2]
        self.hops = bytes[3]

        self.xid = bytes[4:8]

        self.secs = bytes[8:10]
        self.flags = bytes[10:12]

        self.ciaddr = bytes[12:16]
        self.yiaddr = bytes[16:20]
        self.siaddr = bytes[20:24]
        self.giaddr = bytes[24:28]

        self.chaddr = bytes[28:44]
        self.chaddr_overflow = bytes[44:236] #192 ottetti a 0

        self.magic_cookie = bytes[236:240]


        byte_options = []

        for byte in bytes[240:]:
            byte_options.append(byte)

        self.option_messageType = None #53
        self.option_leaseTime = None  #51
        self.option_requestedAddress = None  #50
        self.option_broadcastAddress = None  #28
        self.option_subnetMask = None  #1

        self.options = []
        counter = 0
        while counter < len(byte_options):

            id = byte_options[counter]

            if id == 255:
                self.endmark = 255
                break

            counter += 1
            length = byte_options[counter]
            value = byte_options[counter+1:length+counter+1]

            option = Option(id, length, value)

            if option.id == 53:
                self.option_messageType = option.value[0]
            elif option.id == 51:
                self.option_leaseTime = int.from_bytes(option.value, byteorder='big') #number.to_bytes(4, byteorder = 'big') to reverse
            elif option.id == 50:
                self.option_requestedAddress = option.value
            elif option.id == 28:
                self.option_broadcastAddress = option.value
            elif option.id == 1:
                self.option_subnetMask = option.value
            else:
                self.options.append(option)

            counter += length+1



    def get_type(self):

        return self.option_messageType


    def to_string(self):

        print("OP:", self.op)
        print("HTYPE:", self.htype)
        print("HLEN:", self.hlen)
        print("HOPS:", self.hops)

        print("XID:", self.xid.hex(), ", SECS:", self.secs.hex(), ", FLAGS:", self.flags.hex())

        print("CIADDR:", self.ciaddr.hex(), ", YIADDR:", self.yiaddr.hex(), ", SIADDR:", self.siaddr.hex(), ", GIADDR:", self.giaddr.hex())

        print("CHADDR:", self.chaddr.hex())

        print("MAGIC COOKIE:", self.magic_cookie.hex())

        print("\n                         OPTIONS:")

        print("MESSAGE TYPE:", self.option_messageType)
        print("LEASE TIME:", self.option_leaseTime)
        print("REQUESTED ADDRESS:", self.option_requestedAddress)
        print("BROADCAST ADDRESS:", self.option_broadcastAddress)
        print("SUBNET MASK:", self.option_subnetMask)

        print("\nOTHER OPTIONS:")

        for option in self.options:

            print("ID:", option.id," LENGTH:", option.length, " VALUE:", (bytearray(option.value)).hex())


        print("\nENDMARK:", self.endmark)


    def to_bytes(self):

        #ricrea il pacchetto in bytes
        bytes_list = []
        bytes_list.append(self.op)
        bytes_list.append(self.htype)
        bytes_list.append(self.hlen)
        bytes_list.append(self.hops)

        bytes_list.extend(self.xid)

        bytes_list.extend(self.secs)
        bytes_list.extend(self.flags)

        bytes_list.extend(self.ciaddr)
        bytes_list.extend(self.yiaddr)
        bytes_list.extend(self.siaddr)
        bytes_list.extend(self.giaddr)

        bytes_list.extend(self.chaddr)
        bytes_list.extend(self.chaddr_overflow)

        bytes_list.extend(self.magic_cookie)

        if self.option_messageType is not None:
            bytes_list.append(53)
            bytes_list.append(1)
            bytes_list.append(self.option_messageType)

        if self.option_leaseTime is not None:
            bytes_list.append(51)
            bytes_list.append(4)
            bytes_list.extend(self.option_leaseTime.to_bytes(4, byteorder = 'big')) #from int (seconds) to bytes array

        if self.option_requestedAddress is not None:
            bytes_list.append(50)
            bytes_list.append(4)
            bytes_list.extend(self.option_requestedAddress)

        if self.option_broadcastAddress is not None:
            bytes_list.append(28)
            bytes_list.append(4)
            bytes_list.extend(self.option_broadcastAddress)

        if self.option_subnetMask is not None:
            bytes_list.append(1)
            bytes_list.append(4)
            bytes_list.extend(self.option_subnetMask)

        bytes_list.append(255) #endmark

        return array.array('B', bytes_list).tobytes()
