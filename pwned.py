#!/usr/bin/env python3

import argparse
import base64
from getpass import getpass
from hashlib import sha1, sha256
import requests
import struct
import xml.etree.ElementTree as ET

from Kdbx import Kdbx, Kdbx3, Kdbx4, KdbxHeader


def unlockDatabase(dbPath, keyFilePath=None):
    prompt = f"Enter the password for {dbPath}: "
    pwHash = sha256(getpass(prompt=prompt).encode()).digest()

    key = None
    if keyFilePath:
        # The key hash may be stored in an XML file
        try:
            keyTree = ET.parse(keyFilePath)
            root = keyTree.getroot()
            version = root[0][0].text
            if version == '1.00':
                key = root[1][0].text
        except:
            # Non-XML keys are unsupported at this time
            print("Keyfile wasn't a KeePass XML keyfile. Igorning keyfile.")

    compositeKey = pwHash+base64.b64decode(key) if key else pwHash
    compositeKey = sha256(compositeKey).digest()

    db = None
    with open(dbPath, 'rb') as dbFile:
        sig1 = int(hex(struct.unpack('I', dbFile.read(4))[0]), base=16)
        sig2 = int(hex(struct.unpack('I', dbFile.read(4))[0]), base=16)
        minVer = int(struct.unpack('H', dbFile.read(2))[0])
        majVer = int(struct.unpack('H', dbFile.read(2))[0])

        if majVer == 3:
            db = Kdbx3()
        elif majVer == 4:
            db = Kdbx4()
        else:
            print("File does not appear to be a KDBXv3 or KDBXv4 database!")
            return None

        if (sig1 != db.sig1 and sig2 != db.sig2):
            print("File does not appear to be a KeePass2 database!")
            return None

        db.compositeKey = compositeKey
        db.header.load(dbFile)
        db.load(dbFile)

        if not db.payload:
            return None

    return db


def getBadPasswords(db):
    badPWs = []
    """
    for index, row in db.iterrows():
        pwHash = sha1(row['Password'].encode()).hexdigest().upper()
        firstFive = pwHash[:5]
        remainder = pwHash[5:]

        reqUrl = url + firstFive
        req = requests.get(reqUrl)
        lines = req.text.split('\r\n')
        hashCounts = dict()
        for line in lines:
            h, n = line.split(':')
            hashCounts[h] = int(n)
        if remainder in hashCounts:
            badPWs.append(row['Title'])
    """
    return badPWs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check password database for \
                                     breached passwords.')
    parser.add_argument('filename', type=str)
    parser.add_argument('-k', '--key', help='Database key file path',
                        type=str)
    args = parser.parse_args()
    filename = args.filename

    db = unlockDatabase(args.filename, args.key)

    url = 'https://api.pwnedpasswords.com/range/'

    """
    badPWs = getBadPasswords(db)
    if badPWs:
        print("Bad news! Some of your passwords are compromised. " +
              "The following entries in your database were found in the " +
              "PwnedPasswords database:")
        for badPW in badPWs:
            print(badPW)
    else:
        print("Success! None of your passwords showed up in the " +
              "PwnedPasswords database!")
    del db
    """
