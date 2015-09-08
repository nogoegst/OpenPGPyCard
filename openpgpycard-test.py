from OpenPGPyCard.OpenPGPCard import OpenPGPCard
import hashlib
import binascii
import sys
import Crypto.Util.number

phex = lambda x: print(''.join("{:02x}".format(byte) for byte in x))

if __name__ == "__main__":
    card = OpenPGPCard(transmitter='scd')
    print(card.version)
    print(card.serial)

    print(card.get_url())
    key_auth = card.get_pubkey('auth')
    phex(Crypto.Util.number.long_to_bytes(key_auth.n))
    card.get_keyattr('auth')

    key_auth = card.get_pubkey('sign')
    phex(Crypto.Util.number.long_to_bytes(key_auth.n))
    card.get_keyattr('sign')

    key_auth = card.get_pubkey('decrypt')
    phex(Crypto.Util.number.long_to_bytes(key_auth.n))
    card.get_keyattr('decrypt')
    
    #card.verify_admin_pin()
    #card.gen_keypair()

    #card.set_forcesig(0x00)
    
    card.verify_pin()
    digest = hashlib.sha1("msga".encode('utf-8')).digest()
    hexdigest = binascii.hexlify(digest)
    print("Digest = " + hexdigest.decode('utf-8'))

    signature = card.sign_digest(digest, 'sign')
    phex(signature)
    print("Length of the signature = " + repr(len(signature)*8) + " bits")

    card.verify_pin2()

    signature = card.sign_digest(digest, 'auth')
    phex(signature)
    print("Length of the signature = " + repr(len(signature)*8) + " bits")
