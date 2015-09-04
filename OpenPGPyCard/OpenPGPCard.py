from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker
from smartcard.CardType import ATRCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toBytes
import getpass
import Crypto.Util.number
import Crypto.PublicKey.RSA
from addict import Dict

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
    
    def __init__(self):
        self.ATR = toBytes("3B DA 18 FF 81 B1 FE 75 1F 03 00 31 C5 73 C0 01 40 00 90 00 0C")
        
        self.errorchecker = ISO7816_4ErrorChecker()
        cardtype = ATRCardType(self.ATR)
        cardrequest = CardRequest(timeout=None, cardType=cardtype)
        cardservice = cardrequest.waitforcard()
        self.connection = cardservice.connection

    def connect(self):
        self.connection.connect()
        
    def select_app(self): #Select application
        SELECT = [0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00]
        GET_DATA = [0x00, 0xCA] 
        LE = [0x00]
        data, sw1, sw2 = self.connection.transmit( SELECT )
        self.errorchecker(data, sw1, sw2)

    def get_aid(self): #Get AID
        GET_DATA = [0x00, 0xCA]
        TAG = [0x00, 0x4F]
        LE = [0x00]
        data, sw1, sw2 = self.connection.transmit( GET_DATA + TAG + LE)
        self.errorchecker(data, sw1, sw2)
        aid = bytes(data)
        if len(aid) != 16:
            raise
        AID = Dict()
        (AID.RID, AID.PIX, AID.version, AID.vendor, AID.serial, AID.RFU) = \
        (aid[:5], aid[5:6], aid[6:8], aid[8:10], aid[10:14], aid[14:16])
        self.version = str(AID.version[0]) + '.' + str(AID.version[1])
        self.vendor = AID.vendor
        self.serial = ''.join("{:02X}".format(byte) for byte in AID.serial)
        return AID

    def prepare(self):
        self.connect()
        self.select_app()
        self.get_aid()

    def get_url(self): #Get URL
        GET_DATA = [0x00, 0xCA] 
        TAG = [0x5F, 0x50]
        LE = [0x00]
        data, sw1, sw2 = self.connection.transmit( GET_DATA + TAG + LE)
        self.errorchecker(data, sw1, sw2)
        url = ''.join([chr(x) for x in data])
        return url

    def verify_pin(self):
        PW = getpass.getpass('Enter a PIN for the card '+self.serial+': ')
        return self.verify_pw(0x81, PW)
    
    def verify_pin2(self):
        PW = getpass.getpass('Enter a PIN for the card '+self.serial+': ')
        return self.verify_pw(0x82, PW)

    def verify_admin_pin(self):
        PW = getpass.getpass('Enter Admin PIN for the card '+self.serial+': ')
        return self.verify_pw(0x83, PW)
    
    def verify_pw(self, P2, PW): #Verify PW1
        VERIFY = [0x00, 0x20, 0x00]
        VERIFY.append(P2)
        PW = [ord(x) for x in PW]
        LC = [len(PW)]
        data, sw1, sw2 = self.connection.transmit( VERIFY + LC + PW)
        self.errorchecker(data, sw1, sw2)

    def get_pubkey(self, keypair):
        return self.keypair_action(0x81, keypair)

    def gen_keypair(self, keypair):
        return self.keypair_action(0x80, keypair)



    def keypair_action(self, P1, keypair):
        HEADER = [0x00, 0x47, P1, 0x00]
        LC = [0x02]
        CRTs = {'decryption' : [0xB8,0x00],
                'signature' : [0xB6, 0x00],
                'authentication' : [0xA4, 0x00]}
        CRT = CRTs[keypair]
        LE = [0x00]
        data, sw1, sw2 = self.connection.transmit( HEADER + LC + CRT + LE)
        self.errorchecker(data, sw1, sw2)

        DO = parse_DO(bytearray(data))

        modulus = DO[b'\x7F\x49'][b'\x81']
        exponent = DO[b'\x7F\x49'][b'\x82']

        modulus = Crypto.Util.number.bytes_to_long(modulus)
        exponent = Crypto.Util.number.bytes_to_long(exponent)

        public_key = Crypto.PublicKey.RSA.construct((modulus, exponent))
        return public_key

    def sign_digest(self, digest, keypair):#Sign a digest
        SIGN_CMDs = {'signature' : [0x00, 0x2A, 0x9E, 0x9A],
                     'authentication' : [0x00, 0x88, 0x00, 0x00]}
        DIGEST = [int(x) for x in digest]
        LC = [len(DIGEST)]
        LE = [0x00]
        data, sw1, sw2 = self.connection.transmit( SIGN_CMDs[keypair] + LC + DIGEST + LE)
        self.errorchecker(data, sw1, sw2)
        signature_bytes = bytes(data)
        return signature_bytes

    def set_forcesig(self, value=0x01):
        PUT_DATA = [0x00, 0xDA]
        TAG = [0x00, 0xC4]
        LC = [0x01]
        VALUE = [value]
        data, sw1, sw2 = self.connection.transmit( PUT_DATA + TAG + LC + VALUE )
        self.errorchecker(data, sw1, sw2)

