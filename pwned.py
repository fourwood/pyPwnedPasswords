#!/usr/bin/env python3

import argparse
import base64
from collections import OrderedDict
from Cryptodome.Cipher import Salsa20
from getpass import getpass
from hashlib import sha1, sha256
import requests
import struct
import sys
import xml.etree.ElementTree as ET

from Kdbx import Kdbx3, Kdbx4


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
                key = base64.b64decode(root[1][0].text)
        except ET.ParseError:
            with open(keyFilePath, 'rb') as keyFile:
                key = sha256(keyFile.read()).digest()

    compositeKey = pwHash+key if key else pwHash
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
        db.header.load(dbFile, db.headerFieldSize)
        db.load(dbFile)

        if not db.payload:
            return None

    return db


def getBadPasswords(encryptedPasswords, key):
    iv = bytes.fromhex("e830094b97205d2a")
    s20 = Salsa20.new(key=sha256(key).digest(), nonce=iv)

    badPWs = []
    for site, field, value in encryptedPasswords:
        encValue = base64.b64decode(value)
        zeros = b'\x00' * len(encValue)
        zerosEnc = s20.encrypt(zeros)
        if field != 'Password':
            continue
        pwHash = sha1(bytes([a ^ b for a, b in zip(encValue, zerosEnc)])).hexdigest().upper()
        firstFive = pwHash[:5]
        remainder = pwHash[5:]

        url = 'https://api.pwnedpasswords.com/range/'
        reqUrl = url + firstFive
        req = requests.get(reqUrl)
        lines = req.text.split('\r\n')
        hashCounts = dict()
        for line in lines:
            h, n = line.split(':')
            hashCounts[h] = int(n)
        if remainder in hashCounts:
            badPWs.append(site)

    return badPWs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check KeePass database for" +
                                     " breached passwords.")
    parser.add_argument('filename', type=str)
    parser.add_argument('-k', '--key', help="Database key file path",
                        type=str)
    args = parser.parse_args()
    filename = args.filename

    # TODO: Maybe refactor unlocking more into the db class?
    db = unlockDatabase(args.filename, args.key)

    if not db:
        print("Failed to open password database!")
        sys.exit(1)

    # NOTE: protected entries (e.g. passwords) may still be encrypted at rest
    rootGroup = db.xml.find('Root').find('Group')
    sites = [v.text for v in rootGroup.findall('.//Value[@Protected="True"]/../../String[Key="Title"]/Value')]
    protFields = [v.text for v in rootGroup.findall('.//Value[@Protected="True"]/../Key')]
    protValues = [v.text for v in rootGroup.findall('.//Value[@Protected="True"]')]
    protEntries = ((s, f, v) for s, f, v in zip(sites, protFields, protValues) if v)

    badPWsites = getBadPasswords(protEntries, db.header.streamKey)
    if badPWsites:
        print("Bad news! Some of your passwords are compromised!")
        print("The following entries in your database were found in the " +
              "PwnedPasswords database:")
        for site in badPWsites:
            print(f"- {site}")
        print("(n.b. These sites may be deleted entries or have the " +
              "vulnerable password stored in their history!)")
    else:
        print("Success! None of your passwords showed up in the " +
              "PwnedPasswords database!")

    del protValues
    del protEntries
    del rootGroup
    del db
