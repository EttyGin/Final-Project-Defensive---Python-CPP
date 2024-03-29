"""
This file gathers classes created for the purpose of the server
"""
import base64
import struct
import uuid
from datetime import datetime

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import db


class File:
    def __init__(self, id, fileName, pathName, verified):
        self.ID = id
        self.fileName = fileName
        self.pathName = pathName
        self.verified = verified

    def getId(self):
        return self.ID

    def getFileName(self):
        return self.fileName

    def getPathName(self):
        return self.pathName

    def setVerified(self, verified):
        self.verified = verified


class Client:
    def __init__(self, id, name, publicKey, lastSeen, AESKey):
        self.ID = id
        self.name = name
        self.publicKey = publicKey
        self.lastSeen = lastSeen
        self.AESKey = AESKey

    def getId(self):
        return self.ID

    def getName(self):
        return self.name

    def getPublicKey(self):
        return self.publicKey

    def getAESKey(self):
        return self.AESKey

    def setPublicKey(self, publicKey):
        self.publicKey = publicKey

    def setLastSeen(self, lastSeen):
        self.lastSeen = lastSeen

    def setAESKey(self, AESKey):
        self.AESKey = AESKey


class Response:
    VERSION = 3
    sizes = {
        "ID": 16,
        "fileName": 255,
        "fileSizeInBytes": 4,
        "crc": 4,
    }
    codes = {
        "registSucceed": 1600,
        "registFailed": 1601,
        "AESRegist": 1602,
        "crcValid": 1603,
        "msgConfirm": 1604,
        "AESReconnect": 1605,
        "reconnectFailed": 1606,
        "genericError": 1607
    }

    def __init__(self):
        pass

    def sendRegistSucceed(self, clientId, conn):
        '''
        Sending a registration success message to the client (1600)
        :param clientId: The client that tried to register
        :param conn: An open socket  for sending messages to this client
        '''

        header = struct.pack('<BHI', self.VERSION, self.codes["registSucceed"], self.sizes["ID"])
        payLoad = clientId.bytes

        conn.sendall(header + payLoad)

        print("Server sent registrarion succeed Response")

    def sendRegistFailed(self, conn):
        '''
        Sending a registration failed message to the client (1601)
        :param clientId: The client that tried to register
        :param conn: An open socket  for sending messages to this client
        '''

        header = struct.pack('<BHI', self.VERSION, self.codes["registFailed"], 0)
        conn.sendall(header)

        print("Server sent a registrarion failed Response")

    def sendAES(self, clientId, aesKey, encryptedKey, aesSize, reconnect, conn):
        '''
        Sending an aesKey message to the new / existed client (1602 / 1605)
        :param clientId: The client that waiting
        :param conn: An open socket  for sending messages to this client
        '''
        code = self.codes["AESReconnect"] if reconnect else self.codes["AESRegist"]

        header = struct.pack('<BHI', self.VERSION, code, self.sizes["ID"] + aesSize)
        payLoad = clientId.bytes + encryptedKey

        conn.sendall(header + payLoad)

        print(f"Server sent aes key Response with AES key: {base64.b64encode(aesKey)}")

    def sendCrc(self, clientId, contentSize, filename, Cksum, conn):
        '''
        Sending a message that received a proper file with CRC (1603)
        :param clientId: The client who sent the file
        :param contentSize:The size of the encrypted file
        :param filename: The name of the file
        :param Cksum: CRC
        :param conn: An open socket  for sending messages to this client
        '''
        totalSize = self.sizes["ID"] + self.sizes["fileName"] + self.sizes["fileSizeInBytes"] + self.sizes["crc"]
        header = struct.pack('<BHI', self.VERSION, self.codes["crcValid"], totalSize)
        payLoad = struct.pack('<16sI255sI', clientId.bytes, contentSize, filename, Cksum)

        conn.sendall(header + payLoad)

        print("Server sent crc Response")

    def sendMsgConfirm(self, clientId, conn):
        '''
        Sending a message to confirm receiving message (1604)
        :param clientId: The client that send the message
        :param conn: An open socket  for sending messages to this client
        '''

        header = struct.pack('<BHI', self.VERSION, self.codes["msgConfirm"], self.sizes["ID"])
        payLoad = clientId.bytes

        conn.sendall(header + payLoad)

        print("Server sent confirm receiving Response")

    def sendReconnectFailed(self, clientId, conn):
        '''
        Sending a reconnection failed message to the client (1606)
        :param clientId: The client that tried to reconnect
        :param conn: An open socket for sending messages to this client
        '''

        header = struct.pack('<BHI', self.VERSION, self.codes["reconnectFailed"], self.sizes["ID"])
        payLoad = clientId.bytes

        conn.sendall(header + payLoad)

        print("Server sent confirm receiving Response")

    def sendError(self, conn):
        '''
        Sending a generic error message to the client (1607)
        :param conn: An open socket  for sending messages to this client
        '''

        header = struct.pack('<BHI', self.VERSION, self.codes["genericError"], 0)
        conn.sendall(header)

        print("Server sent an error Response")


class Request:
    DIRECTORY_PATH = 'clients files'
    endHandling = False
    sizes = {
        "ID": 16,
        "version": 1,
        "fileName": 255,
        "code": 2,
        "packet": 2,
        "payloadSize": 4,
        "aesKey": 32,  # ket length = 256 bits
        "header": 23
    }
    codes = {
        "regist": 1025,
        "pkeySend": 1026,
        "reconnect": 1027,
        "fileSend": 1028,
        "validCRC": 1029,
        "invalidCRC": 1030,
        "end": 1031
    }

    def __init__(self, sel, clients, files):
        self.sel = sel
        self.clients = clients
        self.files = files

    def read(self, conn, mask):
        try:
            header = conn.recv(self.sizes["header"])  # Should be ready

            if not header:  # Error - couldn't read
                self.exitClient(conn, self.endHandling)
                return self.clients

            clientId, version, code, payLoadSize = struct.unpack('<{}sBHI'.format(self.sizes["ID"]), header)
            if code:
                if code in self.codes.values():
                    function = ""
                    for funcName, funcCode in self.codes.items():  # finds the function name
                        if code == funcCode:
                            function = funcName

                    if function == "regist":
                        clientId = self.regist(conn, payLoadSize)
                        if clientId == '':
                            self.exitClient(conn, self.endHandling)
                            return
                    else:
                        clientId = uuid.UUID(bytes=clientId)
                        callableFunc = getattr(self, function)  # gets the specific function
                        callableFunc(conn, clientId, payLoadSize)


                else:
                    print(f"Server didn't recognize the code {code}")
                    conn.recv(self.sizes["payloadSize"])
                    Response().sendError(conn)
            else:
                self.exitClient(conn, self.endHandling)

        except ConnectionResetError:
            self.exitClient(conn, self.endHandling)

        return self.clients

    def regist(self, conn, payLoadSize):
        '''
        Handles a registration request (1025)
        :param conn: An open socket for sending response
        :param payLoadSize: The size of the message content to receive
        :return: the id of the client who registed
        '''
        name = conn.recv(payLoadSize).decode("utf-8").replace('\0', '')  # decoding the payLoad - user name
        print(f"Server received a regist request from client: {name}")

        if self.isExistedClient(name):  # exists already - not good
            Response().sendRegistFailed(conn)
            return ""

        else:
            clientId = uuid.uuid4()
            self.addNewClient(name, clientId)
            print("Server created id for this client: ", clientId.hex)
            print("The updated client table: ", self.clients)
            Response().sendRegistSucceed(clientId, conn)
            return clientId

    def pkeySend(self, conn, clientId, payLoadSize):
        '''
        Handles the request to send a public key - receives and updates (1026)
        :param conn: An open socket for sending response
        :param clientId: The client that waiting
        :param payLoadSize: The size of the message content to receive
        :return: the public key
        '''
        print("Server excepted public key request")

        self.addLastSeen(clientId)
        name = conn.recv(self.sizes["fileName"]).decode("utf-8").replace('\0', '')
        pkey = conn.recv(payLoadSize - self.sizes["fileName"])  # .decode("utf-8").replace('\0', '')
        rsaKey = RSA.import_key(pkey)
        self.addRsa(clientId, rsaKey)

        aesKey = get_random_bytes(self.sizes["aesKey"])
        encryptedAesKey = self.encryptAes(rsaKey, aesKey)
        self.addAes(clientId, aesKey)

        Response().sendAES(clientId, aesKey=aesKey, encryptedKey=encryptedAesKey, aesSize=len(encryptedAesKey),
                           reconnect=False, conn=conn)

    def reconnect(self, conn, clientId, payLoadSize):
        '''
        (1027)
        :param conn: An open socket for sending response
        :param clientId: The client that tried to reconnect
        :param payLoadSize:
        :return:
        '''
        origId = clientId
        clientId = clientId.hex
        name = conn.recv(payLoadSize).decode("utf-8").replace('\0', '')  # decoding the payLoad - user name
        print(f"Server received a reconnect request from client: {name}, id: {clientId}")

        ok = True
        pkey = ""
        if clientId in self.clients.keys() and self.clients[clientId].getName() == name:
            self.addLastSeen(origId)
            pkey = self.clients[clientId].getPublicKey()
            if pkey == "":
                ok = False
        else:
            ok = False

        if ok:

            # convert the public_key string to a RSA format
            pkeyInRsa = base64.b64decode(pkey.encode())
            pkeyInRsa = RSA.import_key(pkeyInRsa)

            aesKey = Random.get_random_bytes(self.sizes["aesKey"])
            encryptedAesKey = self.encryptAes(pkeyInRsa, aesKey)
            self.addAes(origId, aesKey)

            Response().sendAES(origId, aesKey=aesKey, encryptedKey=encryptedAesKey, aesSize=len(encryptedAesKey),
                               reconnect=True,
                               conn=conn)
            # print(f"Server sent AES key: {base64.b64encode(aesKey)}")

        else:
            print("Server rejected the reconnection - details do not match")
            self.deleteClient(name, clientId)
            print("The updated client table: ", self.clients)
            Response().sendReconnectFailed(origId, conn)

    def fileSend(self, conn, clientId, payLoadSize):
        '''
        (1028)
        :param conn: An open socket for sending response
        :param clientId: The client that sent the file
        :param payLoadSize:
        :return:
        '''

        print("Server received file from client")
        msgContent = b""
        totalContentSize = 0
        start = True
        while True:
            self.addLastSeen(clientId)

            if not start:
                header = conn.recv(self.sizes["header"])
            else:
                start = False

            contentSize = struct.unpack('I', conn.recv(self.sizes["payloadSize"]))[0]
            origFileSize = struct.unpack('I', conn.recv(self.sizes["payloadSize"]))[0]
            packNum = struct.unpack('H', conn.recv(self.sizes["packet"]))[0]
            totalPack = struct.unpack('H', conn.recv(self.sizes["packet"]))[0]
            fileNameBytes = conn.recv(self.sizes["fileName"])
            fileName = fileNameBytes.decode("utf-8").replace('\0', '')
            msgContent += conn.recv(contentSize)

            print(f"Server got {packNum} part of {fileName}")
            totalContentSize += contentSize

            if self.existsFile(clientId, fileName):
                print("Server has such a file for another client")
                Response().sendError(conn)
                return

            # TODO: maybe not to send response. only in the end
            #           if packNum < totalPack:  # not the end, there is more - TCP has to veripy receiving
            #              Response().sendMsgConfirm(clientId, conn)
            if packNum == totalPack:
                break
        #           else:
        #               Response().sendError(conn)
        #              return

        decryptedContent = self.decrypt(clientId, msgContent)
        #        self.writeToFile(packNum, fileName, decryptedContent)

        db.Db().saveNewFile(fileName, decryptedContent)
        self.addNewFile(clientId, fileName)
        crc = self.calcCrc(decryptedContent)
        print("Server saved the file. The updated files: ", self.files)
        # calculate the crc of the file
        print("crc of the decrypted file is: ", crc)
        Response().sendCrc(clientId, totalContentSize, fileNameBytes, crc, conn)

    def validCRC(self, conn, clientId, payLoadSize):
        '''
        Handles receiving a proper CRC message (1029)
        :param conn: An open socket for sending response
        :param clientId: The client that sent the file
        :param payLoadSize: The size of the message content to receive
        '''
        print("Server excepted valid crc request")
        self.addLastSeen(clientId)

        fileName = conn.recv(payLoadSize).decode("utf-8").replace('\0', '')
        if self.files[fileName].getId() == clientId.hex:  # Verify that it's the corrct file

            self.addVerified(fileName, True)
            print("The updated tables:\nclients: ", self.clients, "\nfiles table: ", self.files)
            Response().sendMsgConfirm(clientId, conn)
            self.endHandling = True


        else:
            Response().sendError(conn)

    def invalidCRC(self, conn, clientId, payLoadSize):
        '''
        Handles receiving an invalid CRC message(1030)
        :param conn: An open socket for sending response
        :param clientId: The client that sent the file
        :param payLoadSize: The size of the message content to receive
        '''

        print("Server excepted invalid crc request")
        self.addLastSeen(clientId)

        fileName = conn.recv(payLoadSize).decode("utf-8").replace('\0', '')
        if self.files[fileName].getId() == clientId.hex:  # Verify that it's the corrct file

            self.addVerified(fileName, False)
            Response().sendMsgConfirm(clientId, conn)

        else:
            Response().sendError(conn)

    def end(self, conn, clientId, payLoadSize):
        '''
        Handles receiving an invalid CRC and exit message (1031)
        :param conn: An open socket for sending response
        :param clientId: The client that sent the file
        :param payLoadSize: The size of the message content to receive
        '''
        print("Server excepted invalid crc request")
        self.addLastSeen(clientId)

        fileName = conn.recv(payLoadSize).decode("utf-8").replace('\0', '')
        if self.files[fileName].getId() == clientId.hex:  # Verify that it's the corrct file

            self.addVerified(fileName, True)
            Response().sendMsgConfirm(clientId, conn)

        else:
            Response().sendError(conn)

    def exitClient(self, conn, end = False):
        self.sel.unregister(conn)
        conn.close()
        details = "finished! "if end else "client left"
        print(f"Server closed the connection - {details}")
        print("The clients now: ", self.clients)

    def isExistedClient(self, name):
        for c in self.clients.values():
            if name == c.getName():
                return True
        return False

    def addNewClient(self, name, clientId):
        '''
        Adds the new client to the database and the held dictionary (clients)
        :param name: The name of the new client
        :param clientId: The id of the client
        '''
        db.Db().addNewClient(name, clientId)
        client = Client(clientId.hex, name, "", datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "")
        self.clients[clientId.hex] = client

    def addLastSeen(self, clientId):
        newTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.Db().addLastSeen(clientId, newTime)
        self.clients[clientId.hex].setLastSeen(newTime)

    def addRsa(self, clientId, pkey):
        pkey = base64.b64encode(pkey.export_key(format='DER')).decode('utf-8')
        db.Db().addRSA(clientId, pkey)
        self.clients[clientId.hex].setPublicKey(pkey)

    def addAes(self, clientId, pkey):
        pkey = base64.b64encode(pkey)
        db.Db().addAES(clientId, pkey)
        self.clients[clientId.hex].setAESKey(pkey)

    def addVerified(self, fileName, verified=False):
        db.Db().addVerified(fileName, verified)
        self.files[fileName].setVerified(verified)

    def addNewFile(self, clientId, fileName):
        '''
        Adds the new file to the database and the held dictionary (clients)
        :param clientId: The id of the client who sent the file
        :param fileName: The name of the new file
        '''
        path = self.DIRECTORY_PATH + "\\" + fileName
        db.Db().addNewFile(clientId, fileName, path)
        file = File(clientId.hex, fileName, path, False)
        self.files[fileName] = file

    def deleteClient(self, name, clientId):
        '''
        Delete the client from the database and the held dictionary (clients)
        :param name: The name of the client to remove
        :param clientId: The id of the client
        '''
        db.Db().deleteClient( clientId)
        del self.clients[clientId]

    def encryptAes(self, publicKey, aesKey):
        cipher = PKCS1_OAEP.new(publicKey)
        return cipher.encrypt(aesKey)

    def calcCrc(self, content):

        # import binascii
        # MASK = 0xFFFFFFFF
        # return binascii.crc32(content) & MASK

        crctab = [0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc,
                  0x17c56b6b, 0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f,
                  0x2f8ad6d6, 0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a,
                  0x384fbdbd, 0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
                  0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75, 0x6a1936c8,
                  0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3,
                  0x709f7b7a, 0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e,
                  0x95609039, 0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
                  0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84,
                  0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d, 0xd4326d90, 0xd0f37027,
                  0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022,
                  0xca753d95, 0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
                  0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077,
                  0x30476dc0, 0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c,
                  0x2e003dc5, 0x2ac12072, 0x128e9dcf, 0x164f8078, 0x1b0ca6a1,
                  0x1fcdbb16, 0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
                  0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb,
                  0x6f52c06c, 0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08,
                  0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d,
                  0x40d816ba, 0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
                  0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692, 0x8aad2b2f,
                  0x8e6c3698, 0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044,
                  0x902b669d, 0x94ea7b2a, 0xe0b41de7, 0xe4750050, 0xe9362689,
                  0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
                  0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683,
                  0xd1799b34, 0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59,
                  0x608edb80, 0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c,
                  0x774bb0eb, 0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
                  0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53, 0x251d3b9e,
                  0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5,
                  0x3f9b762c, 0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48,
                  0x0e56f0ff, 0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
                  0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2,
                  0xe6ea3d65, 0xeba91bbc, 0xef68060b, 0xd727bbb6, 0xd3e6a601,
                  0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604,
                  0xc960ebb3, 0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
                  0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6,
                  0x9ff77d71, 0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad,
                  0x81b02d74, 0x857130c3, 0x5d8a9099, 0x594b8d2e, 0x5408abf7,
                  0x50c9b640, 0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
                  0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd,
                  0x6c47164a, 0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e,
                  0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b,
                  0x0fdc1bec, 0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
                  0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654, 0xc5a92679,
                  0xc1683bce, 0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12,
                  0xdf2f6bcb, 0xdbee767c, 0xe3a1cbc1, 0xe760d676, 0xea23f0af,
                  0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
                  0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5,
                  0x9e7d9662, 0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06,
                  0xa6322bdf, 0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03,
                  0xb1f740b4]

        UNSIGNED = lambda n: n & 0xffffffff

        n = len(content)
        print(content)
        i = c = s = 0
        for ch in content:
            tabidx = (s >> 24) ^ ch
            s = UNSIGNED((s << 8)) ^ crctab[tabidx]

        while n:
            c = n & 0o377
            n = n >> 8
            s = UNSIGNED(s << 8) ^ crctab[(s >> 24) ^ c]
        return UNSIGNED(~s)

    def existsFile(self, clientId, fileName):
        '''
        Check if this name is not valid again
        :param clientId: The client who tried to send the file
        :param fileName: The name to check
        :return: true if there is such a file by another client, otherwise false
        '''
        return fileName in self.files.keys() and self.files[fileName].getId() != clientId.hex

    def decrypt(self, clientId, msgContent):
        iv = bytes([0] * AES.block_size)  # assuming that thae iv is full with zeros

        key = self.clients[clientId.hex].getAESKey()
        aesKey = base64.b64decode(key)

        cipher = AES.new(aesKey, AES.MODE_CBC, iv)

        plaintext = cipher.decrypt(msgContent)

        plaintext = unpad(plaintext, AES.block_size)
        return plaintext

    def create_new_path(self, file_name):
        import os
        new_file_path = os.path.join(self.DIRECTORY_PATH, file_name)
        return new_file_path


