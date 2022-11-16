import socket
import json
import sys

# Create a TCP/IP socket
from time import sleep

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('127.0.0.1', 18018)
sock.connect(server_address)
print('succesfully connected to ' + server_address[0])

try:
    # Send data
    ihaveobject = {
        "type": "ihaveobject",
        "objectid": "0024839ec9632d382486ba7aac7e0bda3b4bda1d4bd79be9ae78e7e1e813ddd8"
        }
    object1 = {"object":{"inputs":[{"outpoint":{"index":0,"txid":"ce175f46aeca15cbb80b66d261519f223d992e23dd268721f4135b58f4497a2e"},"sig":"cbd77bf5cdb2a252aea728d776adab2029a2cc375def7f3196fe423111b9374a71cb6707bbfb3bf6833db4218426f8b9f32a5708cad36476decb6da565209d05"},{"outpoint":{"index":0,"txid":"b5770e009b63dc8d9aa3334dfe913ac098738dc02e4b379f96e663ec86aa81eb"},"sig":"3833f90108952068758a30e287d026e7b74d844026333c904d62dd92351330002996e947c0178f9c2248a1dc1d711101df3a385af15e78afdacd723202f2be0c"}],"outputs":[{"pubkey":"06abdd0a320df08c1e9d00e60c57409b1a6754428806a6d5d7f855885c48d540","value":20}],"type":"transaction"},"type":"object"}
    object2 = {"object":{"inputs":[{"outpoint":{"index":0,"txid":"046cf1a7a2c705f006f530168b629dbc7952ecc9cc663a9e282bfe1875ae9ca0"},"sig":"2807ba9687814b58b6db2028c2108ef77445a9c85fb4621b01342261c18aee6b0b029b1345bbb2daa060accca59c08345e4692944a0b8177243f10cd5626650c"}],"outputs":[{"pubkey":"102485c802d15a228ac9865632e181546c0372e3cc33fcc6d93c5a3eaff1dd00","value":10}],"type":"transaction"},"type":"object"}

    getobject = {"type":"getobject","objectid":"ce175f46aeca15cbb80b66d261519f223d992e23dd268721f4135b58f4497a2e"}


    while True:
        command = input("> ")
        if command == "0":
            sock.sendall(bytes('{"type":"hello","version":"0.8.0","agent":"barone"}\n{"type":"getpeers"}\n', encoding="UTF-8"))
            print(sock.recv(8000).decode("UTF-8"))
        if command == "1":
            print('sending ihaveobject')
            sock.sendall(bytes(json.dumps(ihaveobject) + '\n', encoding="UTF-8"))
            print(sock.recv(8000).decode("UTF-8"))
        if command == "2":
            print('sending object')
            sock.sendall(bytes(json.dumps(object1) + '\n', encoding="UTF-8"))

            if command == "2":
                print('sending object')
                sock.sendall(bytes(json.dumps(object2) + '\n', encoding="UTF-8"))
        if command == "3":
            print('sending getobject')
            sock.sendall(bytes(json.dumps(getobject) + '\n', encoding="UTF-8"))
            print(sock.recv(8000).decode("UTF-8"))

        # data = sock.recv(1024)
        # data = data.decode("UTF-8")
        # print(data)
finally:
        print('closing socket')
        sock.close()