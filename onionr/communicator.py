#!/usr/bin/env python3
'''
Onionr - P2P Microblogging Platform & Social network.

This file contains both the OnionrCommunicate class for communcating with peers
and code to operate as a daemon, getting commands from the command queue database (see core.Core.daemonQueue)
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
import sqlite3, requests, hmac, hashlib, time, sys, os, math, logger, urllib.parse, random
import core, onionrutils, onionrcrypto, onionrproofs, btc, config, onionrplugins as plugins

class OnionrCommunicate:
    def __init__(self, debug, developmentMode):
        '''
            OnionrCommunicate

            This class handles communication with nodes in the Onionr network.
        '''

        self._core = core.Core()
        self._utils = onionrutils.OnionrUtils(self._core)
        self._crypto = onionrcrypto.OnionrCrypto(self._core)

        self.highFailureAmount = 7
        '''
        logger.info('Starting Bitcoin Node... with Tor socks port:' + str(sys.argv[2]))
        try:
            self.bitcoin = btc.OnionrBTC(torP=int(sys.argv[2]))
        except _gdbm.error:
            pass
        logger.info('Bitcoin Node started, on block: ' + self.bitcoin.node.getBlockHash(self.bitcoin.node.getLastBlockHeight()))
        '''
        #except:
        #logger.fatal('Failed to start Bitcoin Node, exiting...')
        #exit(1)

        blockProcessTimer = 0
        blockProcessAmount = 5
        highFailureTimer = 0
        highFailureRate = 10
        heartBeatTimer = 0
        heartBeatRate = 5
        pexTimer = 5 # How often we should check for new peers
        pexCount = 0
        logger.debug('Communicator debugging enabled.')
        torID = open('data/hs/hostname').read()

        self.peerData = {} # Session data for peers (recent reachability, speed, etc)

        if os.path.exists(self._core.queueDB):
            self._core.clearDaemonQueue()

        # Loads in and starts the enabled plugins
        plugins.reload()

        while True:
            command = self._core.daemonQueue()
            # Process blocks based on a timer
            blockProcessTimer += 1
            heartBeatTimer += 1
            pexCount += 1
            if highFailureTimer == highFailureRate:
                highFailureTimer = 0
                for i in self.peerData:
                    if self.peerData[i]['failCount'] == self.highFailureAmount:
                        self.peerData[i]['failCount'] -= 1
            if pexTimer == pexCount:
                self.getNewPeers()
                pexCount = 0
            if heartBeatRate == heartBeatTimer:
                logger.debug('Communicator heartbeat')
                heartBeatTimer = 0
            if blockProcessTimer == blockProcessAmount:
                self.lookupBlocks()
                self.processBlocks()
                blockProcessTimer = 0
            if command != False:
                if command[0] == 'shutdown':
                    logger.info('Daemon recieved exit command.')
                    break
            time.sleep(1)

        return

    def getNewPeers(self):
        '''
            Get new peers
        '''
        peersCheck = 5 # Amount of peers to ask for new peers + keys
        peersChecked = 0
        peerList = list(self._core.listAdders()) # random ordered list of peers
        newKeys = []
        newAdders = []
        if len(peerList) > 0:
            maxN = len(peerList) - 1
        else:
            peersCheck = 0
            maxN = 0

        if len(peerList) > peersCheck:
            peersCheck = len(peerList)

        while peersCheck > peersChecked:
            i = random.randint(0, maxN)
            logger.info('Using ' + peerList[i] + ' to find new peers')
            try:
                newAdders = self.performGet('pex', peerList[i], skipHighFailureAddress=True)
                self._utils.mergeAdders(newAdders)
            except requests.exceptions.ConnectionError:
                logger.info(peerList[i] + ' connection failed')
                continue
            else:
                try:
                    logger.info('Using ' + peerList[i] + ' to find new keys')
                    newKeys = self.performGet('kex', peerList[i], skipHighFailureAddress=True)
                    # TODO: Require keys to come with POW token (very large amount of POW)
                    self._utils.mergeKeys(newKeys)
                except requests.exceptions.ConnectionError:
                    logger.info(peerList[i] + ' connection failed')
                    continue
                else:
                    peersChecked += 1
        return

    def lookupBlocks(self):
        '''
            Lookup blocks and merge new ones
        '''
        peerList = self._core.listAdders()
        blocks = ''
        for i in peerList:
            lastDB = self._core.getAddressInfo(i, 'DBHash')
            if lastDB == None:
                logger.debug('Fetching hash from ' + i + ' No previous known.')
            else:
                logger.debug('Fetching hash from ' + str(i) + ', ' + lastDB + ' last known')
            currentDB = self.performGet('getDBHash', i)
            if currentDB != False:
                logger.debug(i + " hash db (from request): " + currentDB)
            else:
                logger.warn("Error getting hash db status for " + i)
            if currentDB != False:
                if lastDB != currentDB:
                    logger.debug('Fetching hash from ' + i + ' - ' + currentDB + ' current hash.')
                    blocks += self.performGet('getBlockHashes', i)
                if self._utils.validateHash(currentDB):
                    self._core.setAddressInfo(i, "DBHash", currentDB)
        if len(blocks.strip()) != 0:
            logger.debug('BLOCKS:' + blocks)
        blockList = blocks.split('\n')
        for i in blockList:
            if len(i.strip()) == 0:
                continue
            if self._utils.hasBlock(i):
                continue
            logger.debug('Exchanged block (blockList): ' + i)
            if not self._utils.validateHash(i):
                # skip hash if it isn't valid
                logger.warn('Hash ' + i + ' is not valid')
                continue
            else:
                logger.debug('Adding ' +  i + ' to hash database...')
                self._core.addToBlockDB(i)

        return

    def processBlocks(self):
        '''
            Work with the block database and download any missing blocks

            This is meant to be called from the communicator daemon on its timer.
        '''

        for i in self._core.getBlockList(True).split("\n"):
            if i != "":
                logger.warn('UNSAVED BLOCK: ' + i)
                data = self.downloadBlock(i)

        return

    def downloadBlock(self, hash):
        '''
            Download a block from random order of peers
        '''

        peerList = self._core.listAdders()
        blocks = ''
        for i in peerList:
            hasher = hashlib.sha3_256()
            data = self.performGet('getData', i, hash)
            if data == False or len(data) > 10000000:
                continue
            hasher.update(data.encode())
            digest = hasher.hexdigest()
            if type(digest) is bytes:
                digest = digest.decode()
            if digest == hash.strip():
                self._core.setData(data)
                if data.startswith('-txt-'):
                    self._core.setBlockType(hash, 'txt')
                logger.info('Successfully obtained data for ' + hash)
                if len(data) < 120:
                    logger.debug('Block text:\n' + data)
            else:
                logger.warn("Failed to validate " + hash)

        return

    def urlencode(self, data):
        '''
            URL encodes the data
        '''

        return urllib.parse.quote_plus(data)

    def performGet(self, action, peer, data=None, skipHighFailureAddress=False, peerType='tor'):
        '''
            Performs a request to a peer through Tor or i2p (currently only Tor)
        '''

        if not peer.endswith('.onion') and not peer.endswith('.onion/'):
            raise PeerError('Currently only Tor .onion peers are supported. You must manually specify .onion')

        # Store peer in peerData dictionary (non permanent)
        if not peer in self.peerData:
            self.peerData[peer] = {'connectCount': 0, 'failCount': 0, 'lastConnectTime': math.floor(time.time())}
        socksPort = sys.argv[2]
        '''We use socks5h to use tor as DNS'''
        proxies = {'http': 'socks5://127.0.0.1:' + str(socksPort), 'https': 'socks5://127.0.0.1:' + str(socksPort)}
        headers = {'user-agent': 'PyOnionr'}
        url = 'http://' + peer + '/public/?action=' + self.urlencode(action)
        if data != None:
            url = url + '&data=' + self.urlencode(data)
        try:
            if skipHighFailureAddress and self.peerData[peer]['failCount'] > self.highFailureAmount:
                retData = False
                logger.debug('Skipping ' + peer + ' because of high failure rate')
            else:
                logger.debug('Contacting ' + peer + ' on port ' + socksPort)
                r = requests.get(url, headers=headers, proxies=proxies, timeout=(15, 30))
                retData = r.text
        except requests.exceptions.RequestException as e:
            logger.warn(action + " failed with peer " + peer + ": " + str(e))
            retData = False

        if not retData:
            self.peerData[peer]['failCount'] += 1
        else:
            self.peerData[peer]['connectCount'] += 1
            self.peerData[peer]['failCount'] -= 1
            self.peerData[peer]['lastConnectTime'] = math.floor(time.time())
        return retData


shouldRun = False
debug = True
developmentMode = False
if config.get('devmode', True):
    developmentMode = True
try:
    if sys.argv[1] == 'run':
        shouldRun = True
except IndexError:
    pass
if shouldRun:
    try:
        OnionrCommunicate(debug, developmentMode)
    except KeyboardInterrupt:
        sys.exit(1)
        pass
