import socket
import re
import struct
import pickle
import random
from packet import Packet
import sys
import os


retransmission_time = 1

server = None
server_host = "::"
server_port = 8080

last_sequence = -1
acknowledgement = -1
fourway = False
threeway = False
recieved_packet_list = []
sent_packet_list = []
connection_established = False
received_acks_seq = []

UPPER_SEQUENCE = 9000
LOWER_SEQUENCE = 1000
MAX_DATA = 4096
SYN = "SYN"
ACK = "ACK"
PSH = "PSH"
FIN = "FIN"

retransmission_limit = 10
retransmission_attempts = 0
wait_state_time = retransmission_time
received_data = ""

def main():
    try:
        create_socket()
        bind_socket()
        while True:
            accept_packet()
    except Exception as e:
        handle_error("Failed to receive data from client")

def create_socket():
    try:
        global server
        server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except Exception as e:
        handle_error("Failed to create socket server")

def bind_socket():
    try:
        addr = (server_host, server_port)
        server.bind(addr)
        print(f'Server is running and waiting for incoming connections on port {server_port}...')
    except Exception as e:
        handle_error("Failed to bind to the server")

def handle_data(data):
    words = get_words(data)
    word_count = get_word_count(words)
    char_count = get_char_count(words)
    char_freq = get_char_freq(words)
    sorted_chars = sort_dict(char_freq)
    response = format_response(word_count, char_count, sorted_chars)
    return response

def get_words(word_string):
    formatted_string = remove_whitespace(word_string)
    words = formatted_string.split(" ")
    words = [x for x in words if x]
    return words

def get_word_count(words):
    return len(words)

def remove_whitespace(word_string):
    try:
        return re.sub(' +', ' ', word_string)
    except Exception as e:
        handle_error("Failed to remove whitespaces in data")
        exit(1)

def get_char_count(words):
    count = 0
    for word in words:
        count += len(word)
    return count

def get_char_freq(words):
    char_dict = {}
    words = [word.lower() for word in words]
    words = "".join(words)
    for c in words:
        if c in char_dict:
            char_dict[c] += 1
        else:
            char_dict[c] = 1
    return char_dict

def format_response(word_count, char_count, char_freq):
    response = "Word Count: %d\nCharacter Count: %d\nCharacter Frequencies:"%(word_count, char_count)

    for key, value in char_freq.items():
        response += "\n%s: %d"%(key, value)
    response += "\n"
    return response

def sort_dict(char_freq):
    keys = list(char_freq.keys())
    keys.sort()
    return {i: char_freq[i] for i in keys}

def send_syn_ack(address):
    global server, retransmission_time
    if last_sequence < 0:
        handle_error("Invalid sequence number")
    packet = Packet(sequence=last_sequence, acknowledgement=acknowledgement, flags=["SYN", "ACK"])
    send_packet(packet, address)

def send_ack(destination):
    create_packet(destination_address=destination, flags=[ACK])

def send_fin_ack(destination):
    create_packet(destination_address=destination, flags=[FIN, ACK])

def create_sequence():
    global last_sequence
    try:
        last_sequence = random.randint(LOWER_SEQUENCE, UPPER_SEQUENCE)
    except Exception as e:
        handle_error("Failed to initialize sequence.")

def check_flags(packet, address):
    global last_sequence, acknowledgement, fourway, connection_established, threeway, acknowledgement, recieved_packet_list, received_data, received_acks_seq
    if fourway and packet.sequence >= acknowledgement:
        return True
    if connection_established and packet.sequence in received_acks_seq:
        return
    if SYN in packet.flags and len(packet.flags) == 1 and is_packet_recieved(packet) == False and not connection_established:
        print("PACKET START", packet.sequence)
        recieved_packet_list.append(packet)
        create_sequence()
        acknowledgement = packet.sequence + 1
        send_syn_ack(address)
        threeway = True
    elif SYN not in packet.flags and not connection_established and not threeway:
        print("Packet received without a connection...")
        return

    elif is_packet_recieved(packet) == False:                   # checks to see if already in list
        recieved_packet_list.append(packet)                     # if it isnt, it will append
        if packet.sequence == acknowledgement:                  # checks the seq and ack to determine what packet to send
            acknowledgement = packet.sequence + 1
            if threeway:
                if ACK in packet.flags and PSH not in packet.flags and FIN not in packet.flags:
                    print("Connection has successfully been established")
                    connection_established = True
                    received_acks_seq.append(packet.sequence)
                    threeway = False
                    return
                    
            elif ACK in packet.flags and PSH in packet.flags: 
                data = packet.data.decode()
                received_data += data

                if data:
                    send_ack(address)
                else:
                    return
            elif ACK in packet.flags and FIN in packet.flags:
                four_handshake(address)
            elif ACK in packet.flags and len(packet.flags) == 1 and fourway:
                received_acks_seq.append(packet.sequence)
                return True
            else:
                print("Bad flags set in packet")
        else:
            print("Resend the last packet back to client")
            recieved_packet_list.pop()
            print(packet.sequence)
            print(acknowledgement)
            handle_retransmission(address)

    else:       # if is_packet_recieved == True, send the last packet because if we recieve same packet it means client didnt get the last ack from server
        print("Duplicate Packet found. Handling retransmission.")
        handle_retransmission(address)

def create_packet(destination_address, flags=[], data=b''):
    crafter_packet = Packet(sequence=last_sequence, acknowledgement=acknowledgement, flags=flags, data=data)
    send_packet(crafter_packet, destination_address)

def send_packet(packet, address, is_retransmission=False):
    global last_sequence, server, retransmission_time, acknowledgement, sent_graph
    try:
        print(f"Sending {packet.flags}")
        sent_graph.add_packet()
        data = pickle.dumps(packet)
        last_sequence += 1
        if is_retransmission:
            server.sendto(data, address)
            return

        if is_packet_sent(packet) == False:                     # if the packet has not been sent
            server.sendto(data, address)
            sent_packet_list.append(packet)                     # appending the packet to the sent 
        else:                                                   # if the packet has been sent dont append to list but send the last
            return
    except socket.timeout:
        if threeway:
            handle_retransmission(address)
        

        

def get_last_sent_packet():
    return sent_packet_list[-1]

"""
Checks to see if the server has already recieved incoming packet
"""
def is_packet_recieved(packet):
    if len(recieved_packet_list) == 0:
        return False
    
    last_packet = recieved_packet_list[-1]
    if last_packet.sequence != packet.sequence:
        return False
    
    if last_packet.sequence == packet.sequence:
        return True
    
"""
after recieving a retransmisstion from client, server handles it
by sending the last packet.
"""
def handle_retransmission(address):
    global last_sequence, retrans_graph
    print("Retransmitting...")
    retrans_graph.add_packet()
    last_packet = get_last_sent_packet()
    last_sequence -= 1
    send_packet(last_packet, address, True)

"""
Checks to see if the server has already sent the packet
"""
def is_packet_sent(packet):
    if len(sent_packet_list) == 0:
        return False
    
    last_packet = sent_packet_list[-1]
    if last_packet.acknowledgement >= packet.acknowledgement:
        return True
    
    if last_packet.acknowledgement < packet.acknowledgement:
        return False

def accept_packet():
    global wait_state_time, fourway, retransmission_time, last_sequence, acknowledgement, received_graph
    try:
        if fourway:
            server.settimeout(retransmission_time)

        data, address = server.recvfrom(MAX_DATA) 
        packet = pickle.loads(data)
        print(f"Received packet with flags {packet.flags}")
        received_graph.add_packet()
        success = check_flags(packet, address)
        is_packet_recieved(packet)
        return success
    except socket.timeout:
        if fourway:
            return False
        else:
            cleanup(True)
    except Exception as e:
        handle_error(e)

def reset_server():
    global server, last_sequence, acknowledgement, fourway, recieved_packet_list, sent_packet_list, connection_established, received_acks_seq, received_data, retrans_graph, sent_graph, received_graph
    server = None
    connection_established = False
    
    last_sequence = -1
    acknowledgement = -1
    fourway = False
    received_data = ""
    recieved_packet_list.clear()
    sent_packet_list.clear()
    received_acks_seq.clear()
    retrans_graph.reset()
    sent_graph.reset()
    received_graph.reset()

def four_handshake(address):
    global fourway, last_sequence
    send_fin_ack(address)
    fourway = True
    while True:
        success = accept_packet() # Should receive an ack
        if success:
            break
        handle_retransmission(address)
    cleanup(True)

def display_data():
    global received_data
    try:
        response = handle_data(received_data)
        print("\n================================")
        print("Data Received from Client:")
        print(response)
    except Exception as e:
        handle_error("Failed to handle data received")


def handle_error(err_message):
    print(f"Error: {err_message}")
    cleanup(False)

def display_graphs():
    global sent_graph, retrans_graph, received_graph
    print("Displaying packets sent graph")
    failure = sent_graph.run()
    if failure:
        print("Failed: No packets were sent")
    else:
        print("Displaying retransmission graph")
        failure = retrans_graph.run()
        if failure:
            print("Failed: No transmissions were sent")
        
        print("Displaying received packets graph")
        failure = received_graph.run()
        if failure:
            print("Failed: No packets were received")

def cleanup(success):
    global received_data
    display_data()
    print("Closing Connection")
    display_graphs()
    if server:
        server.close()
    if success:
        reset_server()
        main()
        #exit(0)
    exit(1)



main()


# ? Server handle retransmissions
