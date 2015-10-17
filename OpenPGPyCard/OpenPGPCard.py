from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker
from smartcard.CardType import ATRCardType
from smartcard.CardRequest import CardRequest
import getpass
import Crypto.Util.number
import Crypto.PublicKey.RSA
from addict import Dict
import subprocess
from urllib.parse import unquote_to_bytes
import binascii

def bpop(b, l=1):
    p = b[:l]
    del b[:l]
    return bytes(p)

def x690_len(data):
    len_octet = bpop(data)
    if int.from_bytes(len_octet, byteorder='big') >> 7: # long form
        # Initial octet
        len_octets = int.from_bytes(len_octet, byteorder='big') & 0b01111111
        length = bpop(data, len_octets)
    else:
        length = len_octet
    return int.from_bytes(length, byteorder='big')

def parse_DO(data):
    data = bytearray(data)
    DO = Dict()
    header = bpop(data, 2)
    length = x690_len(data)
    data = bytearray(bpop(data, length))
    while len(data) != 0:
        tag = bpop(data)
        tag_length =x690_len(data)
        tag_data = bpop(data, tag_length)
        DO[header][tag]=tag_data
    return DO

class OpenPGPCard():
    
    def __init__(self, transmitter='pcscd'):
        self.errorchecker = ISO7816_4ErrorChecker()
        self.transmitter = transmitter
        if transmitter == 'pcscd':
            self.pcscd_prepare()
        self.get_aid()

    def checkerrors(self, sw1, sw2):
        return self.errorchecker([], sw1, sw2)

    def scd_transmit(self, APDU):
        response = subprocess.check_output(('gpg-connect-agent', '--hex',
                        'scd apdu '+ binascii.hexlify(APDU).decode('ascii'), '/bye'))
        response = response.decode()
        if response[:3] == 'ERR':
            error_msg = response[4:-6]
            print(error_msg)
            raise
        response = response.split('\n')
        data = ' '.join([ line[9:57] for line in response])
        data = bytes.fromhex(data)
        data = unquote_to_bytes(data)
        return (data[:-2], data[-2], data[-1])

    def transmit(self, APDU):
        if self.transmitter == 'pcscd':
            (data, sw1, sw2) = self.connection.transmit(list(APDU))
            data = bytes(data)
        elif self.transmitter == 'scd':
            (data, sw1, sw2) = self.scd_transmit(APDU)
        else:
            raise
        self.checkerrors(sw1, sw2)
        return data

    def wait(self):
        ATR = list(bytes.fromhex("3BDA18FF81B1FE751F030031C573C001400090000C"))
        cardtype = ATRCardType(ATR)
        cardrequest = CardRequest(timeout=None, cardType=cardtype)
        cardservice = cardrequest.waitforcard()
        self.connection = cardservice.connection

    def connect(self):
        self.connection.connect()

    def select_app(self): #Select application
        SELECT = b'\x00\xA4\x04\x00\x06\xD2\x76\x00\x01\x24\x01\x00'
        self.transmit( SELECT )

    def pcscd_prepare(self):
        self.wait()
        self.connect()
        self.select_app()

    def get_aid(self):
        aid = self.get_data(b'\x00\x4F')
        if len(aid) != 16:
            raise
        self.aid = binascii.hexlify(aid).decode('ascii').upper()
        AID = Dict()
        (AID.RID, AID.PIX, AID.version, AID.vendor, AID.serial, AID.RFU) = \
        (aid[:5], aid[5:6], aid[6:8], aid[8:10], aid[10:14], aid[14:16])
        self.version = str(AID.version[0]) + '.' + str(AID.version[1])
        self.vendor = AID.vendor
        self.serial = binascii.hexlify(AID.serial).decode('ascii').upper()
        return AID

    def get_data(self, tag):
        GET_DATA = b'\x00\xCA'
        LE = b'\x00'
        data = self.transmit( GET_DATA + tag + LE)
        return data

    def put_data(self, tag, data):
        PUT_DATA = b'\x00\xDA'
        LC = bytes([len(data)])
        print(LC)
        data = self.transmit( PUT_DATA + tag + LC + data)

    def get_url(self):
        url = self.get_data(b'\x5F\x50')
        url = url.decode('ascii')
        return url

    def get_keyattr(self, key='auth'):
        TAGs = {'decrypt' : b'\x00\xC2',
                'sign' : b'\x00\xC1',
                'auth' : b'\x00\xC3'}
        data = self.get_data(TAGs[key])
        print(binascii.hexlify(data).decode('ascii'))

    def set_keyattr(self, key='auth'):
        TAGs = {'decrypt' : b'\x00\xC2',
                'sign' : b'\x00\xC1',
                'auth' : b'\x00\xC3'}
        alg_id = b'\x01'
        modulus_len = b'\x08\x00'
        exp_len = b'\x00\x20'
        fmt = b'\x00'
        rsa1024 = alg_id + modulus_len + exp_len + fmt
        data = self.put_data(TAGs[key], rsa1024)


    def verify_pin(self):
        PW = getpass.getpass('Enter a PIN for the card '+self.serial+': ')
        return self.verify_pw(b'\x81', PW)
    
    def verify_pin2(self):
        PW = getpass.getpass('Enter a PIN for the card '+self.serial+': ')
        return self.verify_pw(b'\x82', PW)

    def verify_admin_pin(self):
        PW = getpass.getpass('Enter Admin PIN for the card '+self.serial+': ')
        return self.verify_pw(b'\x83', PW)
    
    def verify_pw(self, P2, PW):
        VERIFY = b'\x00\x20\x00' + P2
        PW = PW.encode('ascii')
        LC = bytes([len(PW)])
        self.transmit(VERIFY + LC + PW)

    def get_pubkey(self, keypair):
        return self.keypair_action(b'\x81', keypair)

    def gen_keypair(self, keypair):
        return self.keypair_action(b'\x80', keypair)

    def keypair_action(self, P1, keypair):
        HEADER = b'\x00\x47' + P1 + b'\x00'
        LC = b'\x02'
        CRTs = {'decrypt' : b'\xB8\x00',
                'sign' : b'\xB6\x00',
                'auth' : b'\xA4\x00'}
        CRT = CRTs[keypair]
        LE = b'\x00'
        data = self.transmit( HEADER + LC + CRT + LE)

        DO = parse_DO(data)

        modulus = DO[b'\x7F\x49'][b'\x81']
        exponent = DO[b'\x7F\x49'][b'\x82']

        modulus = Crypto.Util.number.bytes_to_long(modulus)
        exponent = Crypto.Util.number.bytes_to_long(exponent)

        public_key = Crypto.PublicKey.RSA.construct((modulus, exponent))
        return public_key

    def sign_digest(self, digest, keypair):
        SIGNING_KEY = {'sign' : b'\x00\x2A\x9E\x9A',
                     'auth' : b'\x00\x88\x00\x00'}
        LC = bytes([len(digest)])
        LE = b'\x00'
        signature = self.transmit( SIGNING_KEY[keypair] + LC + digest + LE)
        return signature

    def set_forcesig(self, value=b'\x01'):
        PUT_DATA = b'\x00\xDA'
        TAG = b'\x00\xC4'
        LC = b'\x01'
        self.transmit( PUT_DATA + TAG + LC + value )

