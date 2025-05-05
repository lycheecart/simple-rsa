#!/usr/bin/python

import argparse
from hashlib import sha512

class Agent:
    def getDecryptionExponent(self, phi, e):
        lremainder = -1

        ldividend = phi
        rdividend = phi

        ldivisor = e
        rdivisor = 1

        dune = False
        while not dune: #ext euclidean
            lquotient  = ldividend // ldivisor
            lremainder = (ldividend - (lquotient*ldivisor) ) % phi
            rremainder = (rdividend - (rdivisor*lquotient) ) % phi #yes rremainder uses lquotient

            ldividend = ldivisor
            ldivisor  = lremainder

            rdividend = rdivisor
            rdivisor  = rremainder
            if lremainder == 1:
                dune = True
        d = rremainder
        return d

    def relative_prime(p, q):
        r = max(p, q) + 1
        while not isPrime(r):
            r+=1
        return r

    def isPrime(r):
        for i in range(2, r//2 +1):
            if r % i == 0:
                return False
        return True

    def createKeys(self, p, q):
        phi = (p-1)*(q-1)
        n=p*q
        e=3 
#e = relative_prime(p, q) 
#https://crypto.stackexchange.com/questions/13166/method-to-calculating-e-in-rsa
#usually want 65537

        d = self.getDecryptionExponent(phi, e)

        with open(self.privateFilename, "w", encoding="utf-8") as f:
            f.write(str(d) + "\n")
        f.closed

        with open(self.publicFilename, "w", encoding="utf-8") as f:
            f.write(str(p) + "\n")
            f.write(str(q) + "\n")
            f.write(str(e) + "\n")
        f.closed

    def getPublicNumbers(self, keyfilename):
        with open(keyfilename, "r", encoding="utf-8") as f:
            p = int(f.readline())
            q = int(f.readline())
            e = int(f.readline())
        f.closed
        return p, q, e
    
    def getPrivateNumbers(self, keyfilename):
        with open(keyfilename, "r", encoding="utf-8") as f:
            d = int(f.readline())
        f.closed
        return d

    def stringToBytesToInt (self, s):
        sbytes = s.encode("utf-8")
        sint = int.from_bytes(sbytes, byteorder="big")
        return sint

    def UTF8decode (self, i):
        ibytes = i.to_bytes(((i.bit_length()+7)//8), byteorder="big")
        istring = ibytes.decode("utf-8")
        return istring

    def encrypt(self, message, keyfilename):
        p,q,e = self.getPublicNumbers(keyfilename)
        n = p*q
        print(str(message**e % n))

    def decrypt(self, message, privateFilename, publicFilename):
        d = self.getPrivateNumbers(privateFilename)
        p,q,e = self.getPublicNumbers(publicFilename)
        n = p*q
        return (message**d % n)

    def sign(self, message):
        d = self.getPrivateNumbers(self.privateFilename)
        p,q,e = self.getPublicNumbers(self.publicFilename)
        n = p*q
        hash = int.from_bytes(sha512(message).digest(), byteorder="big")
        #hash = hash & (2**(n.bit_length()) -1) #trunc; 2**x -1 is all 1's ;
        signature = (hash**d) % n
        print(hash)
        print(signature)

    def verify(self, message, signature):
        p,q,e = self.getPublicNumbers(self.publicFilename)
        n = p*q
        hash = int.from_bytes(sha512(message).digest(), byteorder="big")
        #hash = hash & (2**(n.bit_length()) -1) #trunc; 2**x -1 is all 1's ;
        hashFromSignature = (signature**e) % n
        print(hash)
        print(hashFromSignature)
        #print(hash == hashFromSignature)

    def messageFromFile(self, filename):
        l = []
        with open(filename, "r") as f:
            for line in f:
                l.append(int(line.strip()))
        f.closed
        return l

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', dest="p", type=int)
    parser.add_argument('-q', dest="q", type=int)
    parser.add_argument('-m', dest="message", default="rutabegas\n\nradishes")
    #parser.add_argument('-m', dest="message", type=int, default=0)

#filename args
    parser.add_argument('-pub',  dest="pubfile", default="./alice_pubkey.txt")
    parser.add_argument('-priv', dest="privfile", default="./alice_privkey.txt")
    parser.add_argument('-mf',   dest="message_filename", default="./alice_message.txt")
    parser.add_argument('-sf',   dest="signature_filename", default="./alice_signature.txt")

#which-service args
    parser.add_argument("--createkeys", action="store_true")
    parser.add_argument("--encrypt", action="store_true")
    parser.add_argument("--decrypt", action="store_true")
    parser.add_argument("--sign", action="store_true")
    parser.add_argument("--verify", action="store_true")

    args = parser.parse_args()

    alice = Agent()
    alice.privateFilename = args.privfile
    alice.publicFilename  = args.pubfile

    if args.createkeys:
        p = args.p
        q = args.q
        alice.createKeys(p, q)
    elif args.encrypt:
        msg = [ord(ch) for ch in args.message]
        for ch in msg:
            alice.encrypt(ch, args.pubfile)
    elif args.decrypt:
        msg = alice.messageFromFile(args.message_filename)
        for ch in msg:
            o = alice.decrypt(ch, args.privfile, args.pubfile)
            print(chr(o) + " ("+str(o)+")")
    elif args.sign:
        alice.sign(args.message)
    elif args.verify:
        with open(args.signature_filename, "r") as f:
            sig = int(line.strip())
        f.closed
        alice.verify(args.message, args.sig)


if __name__ == "__main__":
    main()
