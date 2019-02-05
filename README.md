# pyPwnedPasswords
Check passwords against the PwnedPasswords/HaveIBeenPwned database.

**This program sends a small amount of encrypted information about your passwords over the internet! Use at your own risk.**

This program reads in a KeePass password database (only KDBXv3 currently supported) and checks the SHA1 hash of every password entry in the PwnedPasswords database of breached/hacked passwords.

This is accomplished via the HaveIBeenPwned passwords API, which uses [k-anonymity](https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange) to only transmit a small fraction of your password's SHA1 hash over the network.

Dependencies:
* PyCryptodome, installed under the 'Cryptodome' module/namespace
