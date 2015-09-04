from OpenPGPyCard.OpenPGPCard import OpenPGPCard
import hashlib
import binascii
import sys
import Crypto.Util.number

phex = lambda x: print(''.join("{:02x}".format(byte) for byte in x))

if __name__ == "__main__":
    card = OpenPGPCard()
    card.connect()
    card.select_app() 
    card.get_aid()
    print(card.version)
    print(card.serial)

    print(card.get_url())
    key_auth = card.get_pubkey('authentication')
    phex(Crypto.Util.number.long_to_bytes(key_auth.n))
    key_auth = card.get_pubkey('signature')
    phex(Crypto.Util.number.long_to_bytes(key_auth.n))
    key_auth = card.get_pubkey('decryption')
    phex(Crypto.Util.number.long_to_bytes(key_auth.n))
    card.verify_admin_pin()
    #card.gen_keypair()

    card.set_forcesig(0x00)
    
    sys.exit()
    card.verify_pin()
    digest = hashlib.sha1("msga".encode('utf-8')).digest()
    hexdigest = binascii.hexlify(digest)
    print("Digest = " + hexdigest.decode('utf-8'))

    signature = card.sign_digest(digest, 'signature')
    phex(signature)
    print("Length of the signature = " + repr(len(signature)*8) + " bits")

    card.verify_pin2()

    signature = card.sign_digest(digest, 'authentication')
    phex(signature)
    print("Length of the signature = " + repr(len(signature)*8) + " bits")
