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
import sqlite3, requests, hmac, hashlib, time, sys, os, logger
import core
class OnionrCommunicate:
    def __init__(self, debug, developmentMode):
        ''' OnionrCommunicate

        This class handles communication with nodes in the Onionr network.
        '''
        self._core = core.Core()
        blockProcessTimer = 0
        blockProcessAmount = 5
        logger.debug('Communicator debugging enabled.')
        torID = open('data/hs/hostname').read()

        # get our own PGP fingerprint
        fingerprintFile = 'data/own-fingerprint.txt'
        if not os.path.exists(fingerprintFile):
            self._core.generateMainPGP(torID)
        with open(fingerprintFile,'r') as f:
            self.pgpOwnFingerprint = f.read()
        logger.info('My PGP fingerprint is ' + logger.colors.underline + self.pgpOwnFingerprint + logger.colors.reset + logger.colors.fg.green + '.')

        while True:
            command = self._core.daemonQueue()

            # Process blocks based on a timer
            blockProcessTimer += 1
            if blockProcessTimer == blockProcessAmount:
                self.lookupBlocks()
                self._core.processBlocks()
                blockProcessTimer = 0
            logger.debug('Communicator daemon heartbeat')
            if command != False:
                if command[0] == 'shutdown':
                    logger.warn('Daemon recieved exit command.')
                    break
            time.sleep(1)
        return
    def getRemotePeerKey(self, peerID):
        '''This function contacts a peer and gets their main PGP key.

        This is safe because Tor or I2P is used, but it does not ensure that the person is who they say they are
        '''
        url = 'http://' + peerID + '/public/?action=getPGP'
        r = requests.get(url, headers=headers)
        response = r.text
        return response
    def shareHMAC(self, peerID, key):
        '''This function shares an HMAC key to a peer
        '''
        return
    def getPeerProof(self, peerID):
        '''This function gets the current peer proof requirement'''
        return
    def sendPeerProof(self, peerID, data):
        '''This function sends the proof result to a peer previously fetched with getPeerProof'''
        return

    def lookupBlocks(self):
        '''Lookup blocks and merge new ones'''
        peerList = self._core.listPeers()
        blocks = ''
        for i in peerList:
            lastDB = self._core.getPeerInfo(i, 'blockDBHash')
            currentDB = self.performGet('getDBHash', i)
            if lastDB != currentDB:
                blocks += self.performGet('getBlockHashes', i)
        blockList = blocks.split('\n')
        for i in blockList:
            if not self._core.validateHash(i):
                # skip hash if it isn't valid
                continue
            else:
                logger.debug('Adding ' +  i + ' to hash database...')
                self._core.addToBlockDB(i)

        return

    def performGet(self, action, peer, data=None, type='tor'):
        '''performs a request to a peer through Tor or i2p (currently only tor)'''
        if not peer.endswith('.onion') and not peer.endswith('.onion/'):
            raise PeerError('Currently only Tor .onion peers are supported. You must manually specify .onion')
        socksPort = sys.argv[2]
        proxies = {'http': 'socks5://127.0.0.1:' + str(socksPort), 'https': 'socks5://127.0.0.1:' + str(socksPort)}
        headers = {'user-agent': 'PyOnionr'}
        url = 'http://' + peer + '/public/?action=' + action
        if data != None:
            url = url + '&data=' + data
        try:
            r = requests.get(url, headers=headers, proxies=proxies)
        except requests.exceptions.RequestException:
            return False
        return r.text


shouldRun = False
debug = False
developmentMode = False
if os.path.exists('dev-enabled'):
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
        pass
