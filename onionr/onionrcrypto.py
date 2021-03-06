'''
    Onionr - P2P Microblogging Platform & Social network

    This file handles Onionr's cryptography.
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
import nacl.signing, nacl.encoding, nacl.public, nacl.secret, os, binascii, base64

class OnionrCrypto:
    def __init__(self, coreInstance):
        self._core = coreInstance
        self._keyFile = 'data/keys.txt'
        self.pubKey = None
        self.privKey = None

        # Load our own pub/priv Ed25519 keys, gen & save them if they don't exist
        if os.path.exists(self._keyFile):
            with open('data/keys.txt', 'r') as keys:
                keys = keys.read().split(',')
                self.pubKey = keys[0]
                self.privKey = keys[1]
        else:
            keys = self.generatePubKey()
            self.pubKey = keys[0]
            self.privKey = keys[1]
            with open(self._keyFile, 'w') as keyfile:
                keyfile.write(self.pubKey + ',' + self.privKey)
        return

    def edVerify(self, data, key):
        '''Verify signed data (combined in nacl) to an ed25519 key'''
        key = nacl.signing.VerifyKey(key=key, encoder=nacl.encoding.Base32Encoder)
        retData = ''
        if encodeResult:
            retData = key.verify(data.encode(), encoder=nacl.encoding.Base64Encoder) # .encode() is not the same as nacl.encoding
        else:
            retData = key.verify(data.encode())
        return retData
    
    def edSign(self, data, key, encodeResult=False):
        '''Ed25519 sign data'''
        key = nacl.signing.SigningKey(seed=key, encoder=nacl.encoding.Base32Encoder)
        retData = ''
        if encodeResult:
            retData = key.sign(data.encode(), encoder=nacl.encoding.Base64Encoder) # .encode() is not the same as nacl.encoding
        else:
            retData = key.sign(data.encode())
        return retData

    def pubKeyEncrypt(self, data, pubkey, anonymous=False, encodedData=False):
        '''Encrypt to a public key (Curve25519, taken from base32 Ed25519 pubkey)'''
        retVal = ''

        if encodedData:
            encoding = nacl.encoding.Base64Encoder
        else:
            encoding = nacl.encoding.RawEncoder

        if self.privKey != None and not anonymous:
            ownKey = nacl.signing.SigningKey(seed=self.privKey, encoder=nacl.encoding.Base32Encoder())
            key = nacl.signing.VerifyKey(key=pubkey, encoder=nacl.encoding.Base32Encoder).to_curve25519_public_key()
            ourBox = nacl.public.Box(ownKey, key)
            retVal = ourBox.encrypt(data.encode(), encoder=encoding)
        elif anonymous:
            key = nacl.signing.VerifyKey(key=pubkey, encoder=nacl.encoding.Base32Encoder).to_curve25519_public_key()
            anonBox = nacl.public.SealedBox(key)
            retVal = anonBox.encrypt(data.encode(), encoder=encoding)
        return retVal

    def pubKeyDecrypt(self, data, pubkey, anonymous=False, encodedData=False):
        '''pubkey decrypt (Curve25519, taken from Ed25519 pubkey)'''
        retVal = ''
        if encodedData:
            encoding = nacl.encoding.Base64Encoder
        else:
            encoding = nacl.encoding.RawEncoder
        ownKey = nacl.signing.SigningKey(seed=self.privKey, encoder=nacl.encoding.Base32Encoder())
        if self.privKey != None and not anoymous:
            ourBox = nacl.public.Box(ownKey, pubkey)
            decrypted = ourBox.decrypt(data, encoder=encoding)
        elif anonymous:
            anonBox = nacl.public.SealedBox(ownKey)
            decrypted = anonBox.decrypt(data.encode(), encoder=encoding)
        return decrypted

    def symmetricPeerEncrypt(self, data, peer):
        '''Salsa20 encrypt data to peer (with mac)
            this function does not accept a key, it is a wrapper for encryption with a peer
        '''
        key = self._core.getPeerInfo(4)
        if type(key) != bytes:
            key = self._core.getPeerInfo(2)
        encrypted = self.symmetricEncrypt(data, key, encodedKey=True)
        return encrypted

    def symmetricPeerDecrypt(self, data, peer):
        '''Salsa20 decrypt data from peer (with mac)
        this function does not accept a key, it is a wrapper for encryption with a peer
        '''
        key = self._core.getPeerInfo(4)
        if type(key) != bytes:
            key = self._core.getPeerInfo(2)
        decrypted = self.symmetricDecrypt(data, key, encodedKey=True)
        return decrypted

        return

    def symmetricEncrypt(self, data, key, encodedKey=False, returnEncoded=True):
        '''Encrypt data to a 32-byte key (Salsa20-Poly1305 MAC)'''
        if encodedKey:
            encoding = nacl.encoding.Base64Encoder
        else:
            encoding = nacl.encoding.RawEncoder

        # Make sure data is bytes
        if type(data) != bytes:
            data = data.encode()

        box = nacl.secret.SecretBox(key, encoder=encoding)

        if returnEncoded:
            encoding = nacl.encoding.Base64Encoder
        else:
            encoding = nacl.encoding.RawEncoder

        encrypted = box.encrypt(data, encoder=encoding)
        return encrypted

    def symmetricDecrypt(self, data, key, encodedKey=False, encodedMessage=False, returnEncoded=False):
        '''Decrypt data to a 32-byte key (Salsa20-Poly1305 MAC)'''
        if encodedKey:
            encoding = nacl.encoding.Base64Encoder
        else:
            encoding = nacl.encoding.RawEncoder
        box = nacl.secret.SecretBox(key, encoder=encoding)

        if encodedMessage:
            encoding = nacl.encoding.Base64Encoder
        else:
            encoding = nacl.encoding.RawEncoder
        decrypted = box.decrypt(data, encoder=encoding)
        if returnEncoded:
            decrypted = base64.b64encode(decrypted)
        return decrypted
    
    def generateSymmetricPeer(self, peer):
        '''Generate symmetric key for a peer and save it to the peer database'''
        key = self.generateSymmetric()
        self._core.setPeerInfo(peer, 'forwardKey', key)
        return

    def generateSymmetric(self):
        '''Generate a symmetric key (bytes) and return it'''
        return binascii.hexlify(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE))

    def generatePubKey(self):
        '''Generate a Ed25519 public key pair, return tuple of base64encoded pubkey, privkey'''
        private_key = nacl.signing.SigningKey.generate()
        public_key = private_key.verify_key.encode(encoder=nacl.encoding.Base32Encoder())
        return (public_key.decode(), private_key.encode(encoder=nacl.encoding.Base32Encoder()).decode())