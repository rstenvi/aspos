#!/usr/bin/env python3

import socket
import sys

PORT = 5555
IP = '0.0.0.0'

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (IP, PORT)
sock.bind(server_address)

sock.listen(1)
while True:
	print("Starting on {}:{}".format(IP, PORT))
	connection, client = sock.accept()
	try:
		print("Connection from: {}".format(client))
		while True:
			data = connection.recv(256)
			print("received: '{}'".format(data))
			if data:
				connection.sendall(data)
			else:
				print("Done sending data")
				break
			
	finally:
		connection.close()

