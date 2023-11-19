#!/usr/bin/env python3

import argparse
import os
import socket
import sys

import confundo

parser = argparse.ArgumentParser("Parser")
parser.add_argument("host", help="Set Hostname")
parser.add_argument("port", help="Set Port Number", type=int)
parser.add_argument("file", help="Set File Directory")
args = parser.parse_args()

def start():
    try:
        with confundo.Socket() as sock:
            sock.settimeout(10)

            # Initiating three-way handshake - Send SYN packet
            syn_packet = confundo.Packet()
            syn_packet.header.syn = 1
            syn_packet.header.connection_id = 0  # You can set the connection ID as needed
            sock.sendto(syn_packet.pack(), (args.host, args.port))

            # Receive SYN-ACK response
            syn_ack_packet, server_address = sock.recvfrom(424)  # Adjust the buffer size as per your needs
            syn_ack_packet = confundo.Packet.unpack(syn_ack_packet)
            if syn_ack_packet.header.syn == 1 and syn_ack_packet.header.ack == 1:
                # SYN-ACK received, extract connection ID and update it
                connection_id = syn_ack_packet.header.connection_id

                # Send ACK packet to complete the handshake
                ack_packet = confundo.Packet()
                ack_packet.header.ack = 1
                ack_packet.header.connection_id = connection_id
                sock.sendto(ack_packet.pack(), (args.host, args.port))

                # Now, you can start sending data
                with open(args.file, "rb") as f:
                    data = f.read(412)  # Send data in segments of 412 bytes
                    while data:
                        total_sent = 0
                        while total_sent < len(data):
                            sent = sock.send(data[total_sent:])
                            total_sent += sent
                        data = f.read(412)  # Read the next segment

                # After transmitting the file, send a FIN packet to initiate connection termination
                fin_packet = confundo.Packet()
                fin_packet.header.fin = 1
                fin_packet.header.connection_id = connection_id
                sock.sendto(fin_packet.pack(), (args.host, args.port))

                # Receive ACK for the FIN
                ack_packet, _ = sock.recvfrom(424)  # Adjust the buffer size as needed
                ack_packet = confundo.Packet.unpack(ack_packet)
                if ack_packet.header.ack == 1:
                    print("File transmission completed.")

            else:
                print("Error: Handshake failed.")

    except RuntimeError as e:
        sys.stderr.write(f"ERROR: {e}\n")
        sys.exit(1)

if __name__ == '__main__':
    start()
