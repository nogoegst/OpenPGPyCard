from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker
from smartcard.CardType import ATRCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toBytes
import getpass
import Crypto.Util.number
import Crypto.PublicKey.RSA

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

    def get_url(self): #Get URL
        GET_DATA = [0x00, 0xCA] 
        TAG = [0x5F, 0x50]
        LE = [0x00]
        data, sw1, sw2 = self.connection.transmit( GET_DATA + TAG + LE)
        self.errorchecker(data, sw1, sw2)
        url = ''.join([chr(x) for x in data])
        return url

    def verify_pin(self):
        PW = getpass.getpass('Enter PIN: ')
        return self.verify_pw(0x81, PW)
    
    def verify_admin_pin(self):
        PW = getpass.getpass('Enter Admin PIN: ')
        return self.verify_pw(0x83, PW)
    
    def verify_pw(self, P2, PW): #Verify PW1
        VERIFY = [0x00, 0x20, 0x00]
        VERIFY.append(P2)
        PW = [ord(x) for x in PW]
        LC = [len(PW)]
        data, sw1, sw2 = self.connection.transmit( VERIFY + LC + PW)
        self.errorchecker(data, sw1, sw2)

    def get_pubkey(self):
        return self.keypair_action(0x81)

    def gen_keypair(self):
        return self.keypair_action(0x80)

    def keypair_action(self, P1):
        HEADER = [0x00, 0x47, P1, 0x00]
        LC = [0x02]
        CRT = [0xB6, 0x00]
        LE = [0x00]
        data, sw1, sw2 = self.connection.transmit( HEADER + LC + CRT + LE)
        self.errorchecker(data, sw1, sw2)
        #hexpublickey = ''.join("{:02x}".format(byte) for byte in data)
        #print("Publickey-DO = " + hexpublickey)

        if data[0:2] != [0x7F, 0x49]:
            print("Wrong DO")
            return
        i = 5
        if data[i] != 0x81:
            print("No modulus!")
            return
        i+=1
        modulus_length = data[i]
        i+=1
        modulus = data[i:i+modulus_length]
        hexmodulus = ''.join("{:02x}".format(byte) for byte in modulus)
        #print("n = " + hexmodulus)
        #print("Modulus length  = " + repr(len(modulus)*8) + " bits")
        i+=modulus_length
        if data[i] != 0x82:
            print("No exponent?")
            return 
        i+=1
        exponent_length = data[i]
        i+=1
        exponent = data[i:i+exponent_length]
        hexexponent = ''.join("{:02x}".format(byte) for byte in exponent)
        #print("Exponent = " + hexexponent)

        modulus = Crypto.Util.number.bytes_to_long(bytes(modulus))
        exponent = Crypto.Util.number.bytes_to_long(bytes(exponent))

        public_key = Crypto.PublicKey.RSA.construct((modulus, exponent))
        return public_key

    def sign_digest(self, digest):#Sign a digest
        SIGN_HEADER = [0x00, 0x2A, 0x9E, 0x9A]
        DIGEST = [int(x) for x in digest]
        LC = [len(DIGEST)]
        LE = [0x00]
        data, sw1, sw2 = self.connection.transmit( SIGN_HEADER + LC + DIGEST + LE)
        self.errorchecker(data, sw1, sw2)
        signature_bytes = bytes(data)
        return signature_bytes

