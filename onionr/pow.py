'''
    Onionr - P2P Microblogging Platform & Social network

    Proof of work module
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
import nacl.encoding, nacl.hash, nacl.utils, time, math, threading, binascii, logger
import btc
class POW:
    def pow(self):
        startTime = math.floor(time.time())
        self.hashing = True
        iFound = False # if current thread is the one that found the answer
        answer = ''
        heartbeat = 200000
        hbCount = 0
        while self.hashing:
            block = self.bitcoinNode.getBlockHash(self.bitcoinNode.getLastBlockHeight())
            if hbCount == heartbeat:
                logger.debug('hb')
                logger.debug('using bitcoin block: ' + block)
                hbCount = 0
            hbCount += 1
            token = nacl.hash.blake2b(nacl.utils.random() + block.encode()).decode()
            if self.mainHash[0:self.difficulty] == token[0:self.difficulty]:
                self.hashing = False
                iFound = True
                break
        if iFound:
            logger.info('Found token ' + token)
            endTime = math.floor(time.time())
            logger.info('took ' + str(endTime - startTime))
            self.result = token
    
    def __init__(self, difficulty, bitcoinNode):
        self.foundHash = False
        self.difficulty = difficulty

        logger.debug('Computing difficulty of ' + str(self.difficulty))

        self.mainHash = nacl.hash.blake2b(nacl.utils.random()).decode()
        self.puzzle = self.mainHash[0:self.difficulty]
        self.bitcoinNode = bitcoinNode
        logger.debug('trying to find ' + str(self.mainHash))
        tOne = threading.Thread(name='one', target=self.pow)
        tTwo = threading.Thread(name='two', target=self.pow)
        tThree = threading.Thread(name='three', target=self.pow)
        tOne.start()
        tTwo.start()
        tThree.start()
        return

    def shutdown(self):
        self.hashing = False
        self.puzzle = ''
    
    def changeDifficulty(self, newDiff):
        self.difficulty = newDiff

    def getResult(self):
        '''Returns the result then sets to false, useful to automatically clear the result'''
        try:
            retVal = self.result
        except AttributeError:
            retVal = False
        self.result = False
        return retVal