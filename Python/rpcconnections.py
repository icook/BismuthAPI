"""
Bismuth default/legacy connection layer.
Json over sockets
This file is no more compatible with the Bismuth code, it's been converted to a class
EggPool 2018
"""

import os
import hashlib
import re
import base64
import json
import socket
import time
import threading

from decimal import Decimal
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA

# Logical timeout
LTIMEOUT = 45
# Fixed header length
SLEN = 10


__version__ = '0.1.7'


class Wallet(object):
    def __init__(self, key):
        self.key = key

    @property
    def priv_key(self):
        return self.key.export_key().decode("utf-8")

    @property
    def pub_key(self):
        return self.key.publickey().export_key().decode("utf-8")

    @property
    def address(self):
        # hashed public key
        return hashlib.sha224(self.pub_key.encode("utf-8")).hexdigest()

    def save(self, path):
        output = json.dumps({
            'Private Key': self.priv_key,
            'Public Key': self.priv_key,
            'Address': self.address,
        })
        if os.path.isfile(path):
            raise ValueError("file {} already exists, abort".format(path))
        fo = open(path, 'w')
        fo.write(output)

    @classmethod
    def load(cls, path):
        wallet_dict = json.load(open(path))
        return cls(RSA.import_key(wallet_dict['Private Key']))

    @classmethod
    def generate(cls):
        key = RSA.generate(4096)
        return cls(key)


class Connection(object):
    """Connection to a Bismuth Node. Handles auto reconnect when needed"""

    __slots__ = ('ipport', 'verbose', 'sdef', 'stats', 'last_activity', 'command_lock', 'raw')
    
    def __init__(self, ipport, verbose=False, raw=False):
        """ipport is an (ip, port) tuple"""
        self.ipport = ipport
        self.verbose = verbose
        self.raw = raw
        self.sdef = None
        self.last_activity = 0
        self.command_lock = threading.Lock()
        self.check_connection()

    def check_connection(self):
        """Check connection state and reconnect if needed."""
        if not self.sdef:
            try:
                if self.verbose:
                    print("Connecting to", self.ipport)
                self.sdef = socket.socket()
                self.sdef.connect(self.ipport)
                self.last_activity = time.time()
            except Exception as e:
                self.sdef = None
                raise RuntimeError("Connections: {}".format(e))

    def _send(self, data, slen=SLEN, retry=True):
        """Sends something to the server"""
        self.check_connection()
        try:
            self.sdef.settimeout(LTIMEOUT)
            # Make sure the packet is sent in one call
            sdata = str(json.dumps(data))
            res = self.sdef.sendall(str(len(sdata)).encode("utf-8").zfill(slen)+sdata.encode("utf-8"))
            if self.raw:
                print("sending raw:")
                print(str(len(sdata)).encode("utf-8").zfill(slen)+sdata.encode("utf-8"))
            self.last_activity = time.time()
            # res is always 0 on linux
            if self.verbose:
                print("send ", data)
            return True
        except Exception as e:
            # send failed, try to reconnect
            # TODO: handle tries #
            self.sdef = None
            if retry:
                if self.verbose:
                    print("Send failed ({}), trying to reconnect".format(e))
                self.check_connection()
            else:
                if self.verbose:
                    print("Send failed ({}), not retrying.".format(e))
                return False
            try:
                self.sdef.settimeout(LTIMEOUT)
                # Make sure the packet is sent in one call
                self.sdef.sendall(str(len(str(json.dumps(data)))).encode("utf-8").zfill(slen)+str(json.dumps(data)).encode("utf-8"))
                return True
            except Exception as e:
                self.sdef = None
                raise RuntimeError("Connections: {}".format(e))

    def _receive(self, slen=SLEN):
        """Wait for an answer, for LTIMEOUT sec."""
        self.check_connection()
        self.sdef.settimeout(LTIMEOUT)
        if self.raw:
            print("getting raw:")
        try:
            data = self.sdef.recv(slen)
            if self.raw:
                raw = data
            if not data:
                raise RuntimeError("Socket EOF")
            data = int(data)  # receive length
        except socket.timeout as e:
            self.sdef = None
            return ""
        try:
            chunks = []
            bytes_recd = 0
            while bytes_recd < data:
                chunk = self.sdef.recv(min(data - bytes_recd, 2048))
                if not chunk:
                    raise RuntimeError("Socket EOF2")
                chunks.append(chunk)
                bytes_recd = bytes_recd + len(chunk)
            self.last_activity = time.time()
            if self.raw:
                print(raw + b''.join(chunks))
            segments = b''.join(chunks).decode("utf-8")
            return json.loads(segments)
        except Exception as e:
            """
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            """
            self.sdef = None
            raise RuntimeError("Connections: {}".format(e))

    def command(self, command, options=None):
        """
        Sends a command and return it's raw result.
        options has to be a list.
        Each item of options will be sent separately. So If you ant to send a list, pass a list of list.
        """
        with self.command_lock:
            try:
                self._send(command)
                if options:
                    for option in options:
                        self._send(option, retry=False)
                ret = self._receive()
                return ret
            except Exception as e:
                """
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
                """
                # TODO : better handling of tries and delay between
                if self.verbose:
                    print("Error <{}> sending command, trying to reconnect.".format(e))
                self.check_connection()
                self._send(command)
                if options:
                    for option in options:
                        self._send(option, retry=False)
                ret = self._receive()
                return ret

    def close(self):
        """Close the socket"""
        try:
            self.sdef.close()
        except Exception as e:
            pass

    def height(self):
        return self.command('statusjson')['blocks']

    def mode(self):
        stat = self.command('statusjson')
        if stat['testnet']:
            return 'testnet'
        if stat['regnet']:
            return 'regnet'
        return 'mainnet'

    def address_validate(self, address):
        if re.match ('[abcdef0123456789]{56}', address):
            return True
        else:
            return False

    def send(self, wallet, recipient, amount, openfield='', operation=0):
        if (len(wallet.pub_key)) != 271 and (len(wallet.pub_key)) != 799:
            raise ValueError("Invalid public key length: {}".format(len(wallet.pub_key)))

        public_key_hashed = base64.b64encode(wallet.pub_key.encode('utf-8'))

        print("Sending from address: {}".format(wallet.address))

        # Pulled from essentials.py
        fee = Decimal("0.01") + (Decimal(len(openfield)) / Decimal("100000"))  # 0.01 dust
        print("Paying Fee: {}".format(fee))

        if float(amount) < 0:
            raise Exception("Cannot send negative amounts")

        if len(str(recipient)) != 56:
            raise Exception("Wrong address length")

        timestamp = '%.2f' % time.time()
        sig_dat = (
            str(timestamp),
            str(wallet.address),
            str(recipient),
            '%.8f' % float(amount),
            str(operation),
            str(openfield))

        sig_dat_hash = SHA.new(str(sig_dat).encode("utf-8"))
        signer = PKCS1_v1_5.new(wallet.key)
        signature = signer.sign(sig_dat_hash)
        signature_enc = base64.b64encode(signature)
        txid = signature_enc[:56]

        print("Encoded Signature: {}".format(signature_enc.decode("utf-8")))
        print("Transaction ID: {}".format(txid.decode("utf-8")))

        verifier = PKCS1_v1_5.new(wallet.key)
        if not verifier.verify(sig_dat_hash, signature):
            raise Exception("Invalid signature was generated")

        tx_submit = (
            str(timestamp),
            str(wallet.address),
            str(recipient),
            '%.8f' % float (amount),
            str(signature_enc.decode("utf-8")),
            str(public_key_hashed.decode("utf-8")),
            str(operation),
            str(openfield))
        reply = self.command("mpinsert", [tx_submit])
        print("Node responded with: {}".format(reply))


if __name__ == "__main__":
    print("I'm a module, can't run!")
