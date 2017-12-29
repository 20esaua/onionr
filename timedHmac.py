'''
    Onionr - P2P Microblogging Platform & Social network. Run with 'help' for usage.
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

# Defunct class (and unfinished) since we will just store hashes of HMAC session payloads

import hmac, base64, time, math
class TimedHMAC:
    def __init__(self, base64Key, data, hashAlgo):
        '''
        base64Key = base64 encoded key
        data = data to hash
        expire = time expiry in epoch
        hashAlgo = string in hashlib.algorithms_available

        Maximum of 10 seconds grace period
        '''
        self.data = data
        self.expire = math.floor(time.time())
        self.hashAlgo = hashAlgo
        self.b64Key = base64Key
        generatedHMAC = hmac.HMAC(base64.b64decode(base64Key), digestmod=self.hashAlgo)
        generatedHMAC.update(data.encode() + str(self.expire).encode())
        self.HMACResult = generatedHMAC.hexdigest()
        return

    def check(self, data):
        # Check a hash (and verify time is sane)
        testHash = hmac.HMAC(base64.b64decode(self.b64Key), digestmod=self.hashAlgo)
        testHash.update(data.encode() + str(math.floor(time.time())).encode())
        testHash = testHash.hexdigest()
        if hmac.compare_digest(testHash, self.HMACResult):
            return True
        else:
            for i in range(20):
                testHash = hmac.HMAC(base64.b64decode(self.b64Key), digestmod=self.hashAlgo)
                testHash.update(data.encode() + str(math.floor(time.time()) - i).encode())
                testHash = testHash.hexdigest()
                if hmac.compare_digest(testHash, self.HMACResult):
                    break
            else:
                return False
            return True
