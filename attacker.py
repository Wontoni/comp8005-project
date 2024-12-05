import socket
import sys
import ipaddress
import pickle
import random
from packet import Packet

retransmission_time = 2
retransmission_limit = 10

# Change to ipv4 for connection via IPv4 Address or ipv6 for IPv6
server_port = 8080


file_name = None
server_host = None
client = None

UPPER_SEQUENCE = 9000
LOWER_SEQUENCE = 1000
MAX_DATA = 4096
MAX_HEADER = 256
SYN = "SYN"
ACK = "ACK"
PSH = "PSH"
FIN = "FIN"

packets_sent = []
packets_received = []
received_acks_seq = []
last_sequence = -1
expected_sequence = -1
acknowledgement = -1

processed_data=''

retransimssion_attempts = 0
waiting_state_time = 2

is_threeway = False
is_fourway = False
connection_established = False
expect_fin_ack = False


def main():
    global processed_data
    check_args(sys.argv)
    handle_args(sys.argv)
    processed_data = read_file()

    if processed_data:
        create_socket()
        connect_client()

def check_args(args):
    try:
        if len(args) != 3:
            raise Exception("Invalid number of arguments")
        elif not args[1].endswith('.txt'):
            raise Exception("Invalid file extension, please input a .txt file")
        is_ipv4(args[2]) # Will handle invalid addresses
    except Exception as e:
        handle_error(e)
        exit(1)

def handle_args(args):
    global file_name, server_host
    try:
        file_name = sys.argv[1]
        server_host = sys.argv[2]
    except Exception as e:
        print(e)
        handle_error("Failed to retrieve inputted arguments.")

def create_socket():
    try: 
        global client
        # INET = IPv4 /// INET6 = IPv6
        client = socket.socket((socket.AF_INET6, socket.AF_INET)[is_ipv4(server_host)], socket.SOCK_DGRAM)

    except Exception as e:
        handle_error("Failed to create client socket")

def connect_client():
    try: 
        client.settimeout(10)
        client.connect((server_host, server_port))
        three_handshake()
    except Exception as e:
        print(e)
        handle_error(f"Failed to connect to socket with the address and port - {server_host}:{server_port}")

def read_file():
    try:
        with open(file_name, 'r', errors="ignore") as file:
            content = file.read()
            if not content:
                raise Exception("File is empty.")
            formatted_data = replace_new_lines(content)
            return formatted_data
    except FileNotFoundError:
        handle_error(f"File '{file_name}' not found.")
    except Exception as e:
        handle_error(e)

def replace_new_lines(text_data):
    try:
        res = text_data.replace('\n', ' ')
        return res
    except Exception as e:
        handle_error(e)

def is_ipv4(ip_str):
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        pass

    try:
        ipaddress.IPv6Address(ip_str)
        return False
    except ipaddress.AddressValueError:
        pass
    err_message = "Invalid IP Address found."
    handle_error(err_message)
    
def handle_error(err_message):
    print(f"Error: {err_message}")
    cleanup(False)
    
def display_message(message):
    print(f'Received response\n{message}')
    cleanup(True)

def cleanup(success):
    if client:
        print("Closing Connection")
        client.close()

    if success:
        exit(0)
    exit(1)

def three_handshake():
    global is_threeway, connection_established
    create_sequence()
    send_syn()
    accept_packet()
    is_threeway = True
    send_ack()
    three_handshake_part_two()

def three_handshake_part_two():
    global is_threeway, connection_established
    is_threeway = False
    connection_established = True
    transmit_data()

def four_handshake():
    global is_fourway, last_sequence, acknowledgement, expect_fin_ack
    print("Fourway Handshake started")
    expect_fin_ack = True
    while True:
        send_fin_ack()
        success = waiting_state()
        if success:
            expect_fin_ack = False
            break
    is_fourway = True
    send_ack()

    while True:
        success = waiting_state()
        if success:
            break
    is_fourway = False
    cleanup(True)

def waiting_state():
    print("Waiting...")
    success = accept_packet()
    if success:
        return True
    
    handle_retransmission()
    

def transmit_data():
    try:
        data = processed_data.encode()

        # Split data into chunks
        chunk_size = MAX_DATA - MAX_HEADER
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
        for chunk in chunks:
            send_ack_psh(chunk)
            accept_packet()

        four_handshake()
    except Exception as e:
        handle_error(e)

def create_packet(flags=[], data=b''):
    crafter_packet = Packet(sequence=last_sequence, acknowledgement=acknowledgement, flags=flags, data=data)
    send_packet(crafter_packet)

def create_sequence():
    global last_sequence
    last_sequence = random.randint(LOWER_SEQUENCE, UPPER_SEQUENCE)

def send_packet(packet):
    global last_sequence, packets_sent
    print("Sending packet", packet.flags)

    packets_sent.append(packet)
    last_sequence += 1
    data = pickle.dumps(packet)
    client.sendall(data)

def accept_packet():
    try:
        global retransmission_time, retransimssion_attempts, waiting_state_time, expect_fin_ack, received_acks_seq, acknowledgement
        if is_fourway or is_threeway and not expect_fin_ack:
            client.settimeout(waiting_state_time)
        else:
            client.settimeout(retransmission_time)
        data, address = client.recvfrom(MAX_DATA) 
        packet = pickle.loads(data)
        print("Received packet with flags", packet.flags)
        if expect_fin_ack and packet.flags == [FIN, ACK]:
           received_acks_seq.append(packet.sequence)
           acknowledgement = packet.sequence + 1
           return True 
        
        packets_received.append(packet)
        retransimssion_attempts = 0
        check_flags(packet)
    except socket.timeout as e:
        if is_threeway or is_fourway:
            return True
        handle_retransmission()
    except Exception as e:
        print(e)

def handle_retransmission():
        global retransimssion_attempts, retransmission_limit, last_sequence
        if retransimssion_attempts >= retransmission_limit:
            print("Max retranmissions hit, force ending connection...")
            cleanup(False)
        print("Retransmitting...")
        last_packet_sent = packets_sent.pop()
        last_sequence -= 1
        retransimssion_attempts += 1
        send_packet(last_packet_sent)
        accept_packet()

def check_flags(packet):
    global last_sequence, acknowledgement, is_threeway, connection_established, received_acks_seq
    if connection_established and packet.sequence in received_acks_seq:
        return
    if packet.sequence == acknowledgement and not is_threeway:
        acknowledgement = packet.sequence + 1
        if PSH not in packet.flags and FIN not in packet.flags:
            received_acks_seq.append(packet.sequence)
            return
        elif PSH in packet.flags:
            return
        elif FIN in packet.flags:
            return
        else:
            handle_error("Bad flags received")
    elif SYN in packet.flags and ACK in packet.flags and not connection_established:
        last_sequence = packet.acknowledgement
        acknowledgement = packet.sequence + 1
        return
    else:
        if packet.flags == [SYN, ACK]:
            packets_sent.pop()
            last_sequence -= 1
            is_threeway = True
            connection_established = False
            handle_retransmission()
            three_handshake_part_two()
            return
        handle_retransmission()

def send_syn():
    create_packet(flags=[SYN])

def send_ack_psh(data):
    create_packet(flags=[ACK, PSH], data=data)

def send_ack():
    create_packet(flags=[ACK])

def send_fin_ack():
    create_packet(flags=[FIN, ACK])

def check_packet_received(packet):
    global packets_received, packets_sent
    if packet not in packets_received:
        packets_received.append(packet)
    else:
        if packet.sequence == packets_received[-1].sequence + 1:
            return # Nothin else should be done
        elif packet.sequence > packets_received[-1].sequence + 1:
            handle_retransmission() # Resend the last packet sent
            return
        else:
            for packet in packets_received:
                print(1)


if __name__ == "__main__":
    main()