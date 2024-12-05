class Packet:
    def __init__(self, sequence, acknowledgement=0, flags=[], data=b''):
        """
        Initialize a new Packet object.

        :param sequence: The sequence number of the packet.
        :param acknowledgment: The acknowledgment number of the packet.
        :param flag: The flag indicating the type/status of the packet (e.g., SYN, ACK).
        """
        self.sequence = sequence
        self.acknowledgement = acknowledgement
        self.flags = flags
        self.data = data

    def display_info(self):
        """
        Print the details of the packet.
        """
        print(f"Packet Info - Sequence: {self.sequence}, Ack: {self.acknowledgement}, Flags: {self.flags}, Data: {self.data} ")