#!/usr/bin/env python3

from hashlib import sha1
import pandas as pd
import requests

def getBadPasswords(df):
    badPWs = []
    for index, row in df.iterrows():
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
    return badPWs

if __name__ == "__main__":
    filename = 'pwn.csv'

    url = 'https://api.pwnedpasswords.com/range/'

    pwnDF = pd.read_csv(filename)
    pwnDF = pwnDF.drop(['Group', 'URL', 'Notes'], axis=1)

    badPWs = getBadPasswords(pwnDF)
    if badPWs:
        print("Bad news, some of your passwords are compromised. The following entries in your database matched in the PwnedPasswords database:")
        for badPW in badPWs:
            print(badPW)
    else:
        print("Success! None of your passwords showed up in the PwnedPasswords database!")
    del pwnDF