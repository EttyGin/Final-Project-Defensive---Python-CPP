import selectors
import socket

import db
from objects import Request

DEFAULT_PORT = 1256
PORT_FILE = "port.info"
HOST = ''
PACKET_SIZE = 1024
sel = selectors.DefaultSelector()

clients = {}
files = {}


def getPort():
    try:
        with open(PORT_FILE, "r") as f:
            port = int(f.read())
    except FileNotFoundError:
        print(f"Warning: File '{PORT_FILE}' does not exist. Default usage: {DEFAULT_PORT}")
        port = DEFAULT_PORT
    return port


def accept(sock, mask):
    conn, addr = sock.accept()  # Should be ready
    print('accepted', conn, 'from', addr)
    conn.setblocking(False)
    sel.register(conn, selectors.EVENT_READ, Request(sel, clients, files).read)


def main():
    global clients
    global files
    port = getPort()

    database = db.Db()
    clients, files = database.getClients(), database.getFiles()
    print("The initial state of the database:")
    database.printClients()
    print("The initial state of the dictionaries:")
    print("clients: ", clients, "\nfiles: ", files)

    sock = socket.socket()
    sock.bind(('localhost', port))
    sock.listen(100)
    sock.setblocking(False)
    print("Server is ready")
    sel.register(sock, selectors.EVENT_READ, accept)

    while True:
        events = sel.select()
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)


if __name__ == '__main__':
    main()
