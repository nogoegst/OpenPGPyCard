from OpenPGPyCard.OpenPGPCard import OpenPGPCard
import hashlib
import binascii

phex = lambda x: print(''.join("{:02x}".format(byte) for byte in x))

if __name__ == "__main__":
    card = OpenPGPCard()
    card.connect()
    card.select_app() 
    aid = card.get_aid()
    phex(aid.version)
    phex(aid.serial)

    print(card.get_url())
    #card.get_pubkey()
    #card.verify_admin_pin()
    #card.gen_keypair()
    
    card.verify_pin()
    digest = hashlib.sha1("msga".encode('utf-8')).digest()
    hexdigest = binascii.hexlify(digest)
    print("Digest = " + hexdigest.decode('utf-8'))

    signature = card.sign_digest(digest)
    phex(signature)
    print("Length of the signature = " + repr(len(signature)*8) + " bits")

    card.verify_pin2()

    signature = card.sign_digest_with_auth(digest)
    phex(signature)
    print("Length of the signature = " + repr(len(signature)*8) + " bits")
