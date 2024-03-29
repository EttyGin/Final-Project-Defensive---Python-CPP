"""
This file is responsible for implementing all database handling
"""

import base64
import os
import sqlite3
from datetime import datetime
import objects

dbFile = 'defensive.db'
directoryPath = 'clients files'


class Db:
    def __init__(self):
        if os.path.isfile(dbFile):
            connection = sqlite3.connect(dbFile)
            cursor = connection.cursor()

            self.clients = loadClients(cursor)
            self.files = loadFiles(cursor)

            connection.close()

        else:  # create - first time
            createDirc()

            connection = sqlite3.connect(dbFile)
            cursor = connection.cursor()

            clientsQuery = '''
            CREATE TABLE IF NOT EXISTS clients (
                ID char(16) PRIMARY KEY,
                Name varchar(255),
                PublicKey char(255),
                lastSeen DATETIME,
                AESKey varchar(255)
                )
            '''

            filesQuery = '''
            CREATE TABLE IF NOT EXISTS files (
                ID char(16),
                FileName varchar(255),
                PathName varchar(255) PRIMARY KEY,
                Verified boolean
                )
            '''

            cursor.execute(clientsQuery)
            cursor.execute(filesQuery)

            connection.commit()
            connection.close()

            self.clients, self.files = {}, {}
        return

    def getClients(self):
        return self.clients

    def getFiles(self):
        return self.files

    def printClients(self):
        connection = sqlite3.connect(dbFile)
        cursor = connection.cursor()

        cursor.execute('SELECT * FROM clients')
        print(cursor.fetchall())

    def addNewClient(self, name, id):
        query = '''
        INSERT INTO clients(ID, Name, PublicKey, LastSeen, AESKey) VALUES (?,?,?,?,?)
        '''
        parameters = (id.hex, name, '', datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '')
        executeQuery(query, parameters)

    def deleteClient(self, id):
        query = '''
        DELETE FROM clients WHERE ID = ?
        '''
        parameters = (id)  # .hex)
        executeQuery(query, parameters)

    def addNewFile(self, id, fileName, path):

        query = '''
           INSERT INTO files(ID, FileName , PathName ,Verified)
            VALUES (?, ?, ?, ?)
           '''
        parameters = (id.hex, fileName, path, False)
        executeQuery(query, parameters)

    def addRSA(self, id, pkey):
        '''
        Add the public key for a client in his row in the db
        :param id: The client's ID
        :param pkey: The public key sent by the client
        '''
        query = '''
        UPDATE clients SET PublicKey = ? WHERE ID = ?
        '''
        parameters = (pkey, id.hex)
        executeQuery(query, parameters)

    def addAES(self, id, aes):
        '''
        Add the aes key for a client in his row in the db
        :param id: The client's ID
        :param aes: The aes that was created for the client
        '''
        query = '''
        UPDATE clients SET AESKey = ? WHERE ID = ?
        '''
        parameters = (base64.b64encode(aes), id.hex)
        executeQuery(query, parameters)

    def addVerified(self, fileName, verified):
        '''
        Add a  verify value for a file in its row in the DB
        :param fileName: The fileName that being updated
        :param verified: The verify value
        '''

        query = '''
        UPDATE files set Verified= ? where PathName= ? 
        '''
        parameters = (verified, fileName)
        executeQuery(query, parameters)

    def addLastSeen(self, id, lastSeen):
        '''
        Updates the time of the last communication with a client
        :param id: The id of the specific client being updated
        :param lastSeen: Last time to update
        '''
        query = '''
        UPDATE clients set LastSeen= ? where ID= ?
        '''
        parameters = (lastSeen, id.hex)
        executeQuery(query, parameters)

    def saveNewFile(self, name, content):
        path = directoryPath + "\\" + name

        try:
            with open(path, 'wb') as new_file:
                new_file.write(content)
        except IOError as e:
            print(f"Error: {e}")


def createDirc():
    '''
    יוצר את תיקיית הלקוחות אם לא קיימת
    :return:
    '''
    if not os.path.exists(directoryPath):
        os.makedirs(directoryPath)


def loadClients(cursor):
    clients = {}
    cursor.execute('SELECT * FROM clients')
    clientsDate = cursor.fetchall()

    for line in clientsDate:
        id, name, pkey, lastSeen, AESKey = line
        # print(id, name, pkey, lastSeen, AESKey)
        clients[id] = objects.Client(id, name, pkey, lastSeen, AESKey)

    return clients


def loadFiles(cursor):
    files = {}
    cursor.execute('SELECT * FROM files')
    filesDate = cursor.fetchall()

    for line in filesDate:
        clientID, fileName, path, verified = line
        # print(clientID, fileName, path, verified)
        files[fileName] = objects.File(clientID, fileName, path, verified)

    return files


def executeQuery(query, parameters):
    try:
        connection = sqlite3.connect(dbFile)
        cursor = connection.cursor()

        cursor.execute(query, parameters)

        connection.commit()
        connection.close()
    except Exception as e:
        print(e)