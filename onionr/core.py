'''
    Onionr - P2P Microblogging Platform & Social network

    Core Onionr library, useful for external programs. Handles peer & data processing
'''
'''
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''
import sqlite3, os, sys, time, math, base64, tarfile, getpass, simplecrypt, hashlib, nacl, logger
#from Crypto.Cipher import AES
#from Crypto import Random
import netcontroller

import onionrutils, onionrcrypto, btc

if sys.version_info < (3, 6):
    try:
        import sha3
    except ModuleNotFoundError:
        logger.fatal('On Python 3 versions prior to 3.6.x, you need the sha3 module')
        sys.exit(1)

class Core:
    def __init__(self):
        '''
            Initialize Core Onionr library
        '''
        self.queueDB = 'data/queue.db'
        self.peerDB = 'data/peers.db'
        self.blockDB = 'data/blocks.db'
        self.blockDataLocation = 'data/blocks/'
        self.addressDB = 'data/address.db'

        if not os.path.exists('data/'):
            os.mkdir('data/')
        if not os.path.exists('data/blocks/'):
            os.mkdir('data/blocks/')
        if not os.path.exists(self.blockDB):
            self.createBlockDB()
            
        self._utils = onionrutils.OnionrUtils(self)
        # Initialize the crypto object
        self._crypto = onionrcrypto.OnionrCrypto(self)

        return

    def addPeer(self, peerID, name=''):
        '''
            Adds a public key to the key database (misleading function name)

            DOES NO SAFETY CHECKS if the ID is valid, but prepares the insertion
        '''
        # This function simply adds a peer to the DB
        if not self._utils.validatePubKey(peerID):
            return False
        conn = sqlite3.connect(self.peerDB)
        c = conn.cursor()
        t = (peerID, name, 'unknown')
        c.execute('INSERT INTO peers (id, name, dateSeen) VALUES(?, ?, ?);', t)
        conn.commit()
        conn.close()
        return True

    def addAddress(self, address):
        '''Add an address to the address database (only tor currently)'''
        if self._utils.validateID(address):
            conn = sqlite3.connect(self.addressDB)
            c = conn.cursor()
            t = (address, 1)
            c.execute('INSERT INTO adders (address, type) VALUES(?, ?);', t)
            conn.commit()
            conn.close()
            return True
        else:
            return False

    def removeAddress(self, address):
        '''Remove an address from the address database'''
        if self._utils.validateID(address):
            conn = sqlite3.connect(self.addressDB)
            c = conn.cursor()
            t = (address,)
            c.execute('Delete from adders where address=?;', t)
            conn.commit()
            conn.close()
            return True
        else:
            return False 

    def createAddressDB(self):
        '''
            Generate the address database

            types:
                1: I2P b32 address
                2: Tor v2 (like facebookcorewwwi.onion)
                3: Tor v3
        '''
        conn = sqlite3.connect(self.addressDB)
        c = conn.cursor()
        c.execute('''CREATE TABLE adders(
            address text,
            type int,
            knownPeer text,
            speed int,
            success int,
            DBHash text,
            failure int
            );
        ''')
        conn.commit()
        conn.close()

    def createPeerDB(self):
        '''
            Generate the peer sqlite3 database and populate it with the peers table.
        '''
        # generate the peer database
        conn = sqlite3.connect(self.peerDB)
        c = conn.cursor()
        c.execute('''CREATE TABLE peers(
            ID text not null,
            name text,
            adders text,
            blockDBHash text,
            forwardKey text,
            dateSeen not null,
            bytesStored int,
            trust int);
        ''')
        conn.commit()
        conn.close()
        return

    def createBlockDB(self):
        '''
            Create a database for blocks

            hash - the hash of a block
            dateReceived - the date the block was recieved, not necessarily when it was created
            decrypted - if we can successfully decrypt the block (does not describe its current state)
            dataType - data type of the block
            dataFound - if the data has been found for the block
            dataSaved - if the data has been saved for the block
        '''
        if os.path.exists(self.blockDB):
            raise Exception("Block database already exists")
        conn = sqlite3.connect(self.blockDB)
        c = conn.cursor()
        c.execute('''CREATE TABLE hashes(
            hash text not null,
            dateReceived int,
            decrypted int,
            dataType text,
            dataFound int,
            dataSaved int);
        ''')
        conn.commit()
        conn.close()

        return

    def addToBlockDB(self, newHash, selfInsert=False):
        '''
            Add a hash value to the block db

            Should be in hex format!
        '''
        if not os.path.exists(self.blockDB):
            raise Exception('Block db does not exist')
        if self._utils.hasBlock(newHash):
            return
        conn = sqlite3.connect(self.blockDB)
        c = conn.cursor()
        currentTime = math.floor(time.time())
        if selfInsert:
            selfInsert = 1
        else:
            selfInsert = 0
        data = (newHash, currentTime, 0, '', 0, selfInsert)
        c.execute('INSERT INTO hashes VALUES(?, ?, ?, ?, ?, ?);', data)
        conn.commit()
        conn.close()

        return

    def getData(self,hash):
        '''
            Simply return the data associated to a hash
        '''
        try:
            dataFile = open(self.blockDataLocation + hash + '.dat')
            data = dataFile.read()
            dataFile.close()
        except FileNotFoundError:
            data = False

        return data

    def setData(self, data):
        '''
            Set the data assciated with a hash
        '''
        data = data.encode()
        hasher = hashlib.sha3_256()
        hasher.update(data)
        dataHash = hasher.hexdigest()
        if type(dataHash) is bytes:
            dataHash = dataHash.decode()
        blockFileName = self.blockDataLocation + dataHash + '.dat'
        if os.path.exists(blockFileName):
            pass # TODO: properly check if block is already saved elsewhere
            #raise Exception("Data is already set for " + dataHash)
        else:
            blockFile = open(blockFileName, 'w')
            blockFile.write(data.decode())
            blockFile.close()

        conn = sqlite3.connect(self.blockDB)
        c = conn.cursor()
        c.execute("UPDATE hashes SET dataSaved=1 WHERE hash = '" + dataHash + "';")
        conn.commit()
        conn.close()

        return dataHash

    def dataDirEncrypt(self, password):
        '''
            Encrypt the data directory on Onionr shutdown
        '''
        if os.path.exists('data.tar'):
            os.remove('data.tar')
        tar = tarfile.open("data.tar", "w")
        for name in ['data']:
            tar.add(name)
        tar.close()
        tarData = open('data.tar', 'r',  encoding = "ISO-8859-1").read()
        encrypted = simplecrypt.encrypt(password, tarData)
        open('data-encrypted.dat', 'wb').write(encrypted)
        os.remove('data.tar')

        return

    def dataDirDecrypt(self, password):
        '''
            Decrypt the data directory on startup
        '''
        if not os.path.exists('data-encrypted.dat'):
            return (False, 'encrypted archive does not exist')
        data = open('data-encrypted.dat', 'rb').read()
        try:
            decrypted = simplecrypt.decrypt(password, data)
        except simplecrypt.DecryptionException:
            return (False, 'wrong password (or corrupted archive)')
        else:
            open('data.tar', 'wb').write(decrypted)
            tar = tarfile.open('data.tar')
            tar.extractall()
            tar.close()

        return (True, '')

    def daemonQueue(self):
        '''
            Gives commands to the communication proccess/daemon by reading an sqlite3 database

            This function intended to be used by the client. Queue to exchange data between "client" and server.
        '''
        retData = False
        if not os.path.exists(self.queueDB):
            conn = sqlite3.connect(self.queueDB)
            c = conn.cursor()
            # Create table
            c.execute('''CREATE TABLE commands
                        (id integer primary key autoincrement, command text, data text, date text)''')
            conn.commit()
        else:
            conn = sqlite3.connect(self.queueDB)
            c = conn.cursor()
            for row in c.execute('SELECT command, data, date, min(ID) FROM commands group by id'):
                retData = row
                break
            if retData != False:
                c.execute('DELETE FROM commands WHERE id=?;', (retData[3],))
        conn.commit()
        conn.close()

        return retData

    def daemonQueueAdd(self, command, data=''):
        '''
            Add a command to the daemon queue, used by the communication daemon (communicator.py)
        '''
        # Intended to be used by the web server
        date = math.floor(time.time())
        conn = sqlite3.connect(self.queueDB)
        c = conn.cursor()
        t = (command, data, date)
        c.execute('INSERT INTO commands (command, data, date) VALUES(?, ?, ?)', t)
        conn.commit()
        conn.close()

        return

    def clearDaemonQueue(self):
        '''
            Clear the daemon queue (somewhat dangerous)
        '''
        conn = sqlite3.connect(self.queueDB)
        c = conn.cursor()
        try:
            c.execute('delete from commands;')
            conn.commit()
        except:
            pass
        conn.close()

        return
    
    def listAdders(self, randomOrder=True, i2p=True):
        '''
            Return a list of addresses
        '''
        conn = sqlite3.connect(self.addressDB)
        c = conn.cursor()
        if randomOrder:
            addresses = c.execute('SELECT * FROM adders ORDER BY RANDOM();')
        else:
            addresses = c.execute('SELECT * FROM adders;')
        addressList = []
        for i in addresses:
            addressList.append(i[0])
        conn.close()
        return addressList

    def listPeers(self, randomOrder=True):
        '''
            Return a list of public keys (misleading function name)

            randomOrder determines if the list should be in a random order
        '''
        conn = sqlite3.connect(self.peerDB)
        c = conn.cursor()
        payload = ""
        if randomOrder:
            payload = 'SELECT * FROM peers ORDER BY RANDOM();'
        else:
            payload = 'SELECT * FROM peers;'
        peerList = []
        for i in c.execute(payload):
            if type(i[2] != None):
                peerList.append(i[2])
        peerList.append(self._crypto.pubKey)
        conn.close()
        return peerList

    def getPeerInfo(self, peer, info):
        '''
            Get info about a peer from their database entry

            id text             0
            name text,          1
            pubkey text,        2
            adders text,        3
            forwardKey text,    4
            dateSeen not null,  5
            bytesStored int,    6
            trust int           7
        '''
        conn = sqlite3.connect(self.peerDB)
        c = conn.cursor()
        command = (peer,)
        infoNumbers = {'id': 0, 'name': 1, 'pubkey': 2, 'adders': 3, 'forwardKey': 4, 'dateSeen': 5, 'bytesStored': 6, 'trust': 7}
        info = infoNumbers[info]
        iterCount = 0
        retVal = ''
        for row in c.execute('SELECT * from peers where id=?;', command):
            for i in row:
                if iterCount == info:
                    retVal = i
                    break
                else:
                    iterCount += 1
        conn.close()

        return retVal

    def setPeerInfo(self, peer, key, data):
        '''
            Update a peer for a key
        '''
        conn = sqlite3.connect(self.peerDB)
        c = conn.cursor()
        command = (data, peer)
        # TODO: validate key on whitelist
        if key not in ('id', 'name', 'pubkey', 'blockDBHash', 'forwardKey', 'dateSeen', 'bytesStored', 'trust'):
            raise Exception("Got invalid database key when setting peer info")
        c.execute('UPDATE peers SET ' + key + ' = ? WHERE id=?', command)
        conn.commit()
        conn.close()
        return

    def getAddressInfo(self, address, info):
        '''
            Get info about an address from its database entry

            address text, 0
            type int, 1
            knownPeer text, 2
            speed int, 3
            success int, 4
            DBHash text, 5
            failure int 6
        '''
        conn = sqlite3.connect(self.addressDB)
        c = conn.cursor()
        command = (address,)
        infoNumbers = {'address': 0, 'type': 1, 'knownPeer': 2, 'speed': 3, 'success': 4, 'DBHash': 5, 'failure': 6}
        info = infoNumbers[info]
        iterCount = 0
        retVal = ''
        for row in c.execute('SELECT * from adders where address=?;', command):
            for i in row:
                if iterCount == info:
                    retVal = i
                    break
                else:
                    iterCount += 1
        conn.close()
        return retVal

    def setAddressInfo(self, address, key, data):
        '''
            Update an address for a key
        '''
        conn = sqlite3.connect(self.addressDB)
        c = conn.cursor()
        command = (data, address)
        # TODO: validate key on whitelist
        if key not in ('address', 'type', 'knownPeer', 'speed', 'success', 'DBHash', 'failure'):
            raise Exception("Got invalid database key when setting address info")
        c.execute('UPDATE adders SET ' + key + ' = ? WHERE address=?', command)
        conn.commit()
        conn.close()
        return

    def getBlockList(self, unsaved=False):
        '''
            Get list of our blocks
        '''
        conn = sqlite3.connect(self.blockDB)
        c = conn.cursor()
        retData = ''
        if unsaved:
            execute = 'SELECT hash FROM hashes WHERE dataSaved != 1;'
        else:
            execute = 'SELECT hash FROM hashes;'
        for row in c.execute(execute):
            for i in row:
                retData += i + "\n"

        return retData

    def getBlocksByType(self, blockType):
        '''
            Returns a list of blocks by the type
        '''
        conn = sqlite3.connect(self.blockDB)
        c = conn.cursor()
        retData = ''
        execute = 'SELECT hash FROM hashes WHERE dataType=?;'
        args = (blockType,)
        for row in c.execute(execute, args):
            for i in row:
                retData += i + "\n"

        return retData.split('\n')

    def setBlockType(self, hash, blockType):
        '''
            Sets the type of block
        '''

        conn = sqlite3.connect(self.blockDB)
        c = conn.cursor()
        c.execute("UPDATE hashes SET dataType='" + blockType + "' WHERE hash = '" + hash + "';")
        conn.commit()
        conn.close()

        return
