from Cryptodome.Cipher import AES
from enum import Enum
import zlib
from hashlib import sha256
import struct
import xml.etree.ElementTree as ET

import base64

class CipherId(Enum):
    AES128 = 0x61ab05a1946441c38d743a563df8dd35
    AES256 = 0x31c1f2e6bf714350be5805216afc5aff
    CHACHA20 = 0xd6038a2b8b6f4cb5a524339a31dbb59a


class HeaderField(Enum):
    END = 0
    COMMENT = 1
    CIPHERID = 2
    COMPRESSION = 3
    MASTERSEED = 4
    TRANSFORMSEED = 5
    ROUNDS = 6
    ENCRYPTIONIV = 7
    STREAMKEY = 8
    STARTBYTES = 9
    INNERSTREAMID = 10
    KDFPARAMS = 11
    CUSTOMDATA = 12


class KdbxHeader:
    def __init__(self):
        self._majorVersion = 0
        self._minorVersion = 0
        self._cipherId = None
        self._isCompressed = None
        self._masterSeed = None
        self._transformSeed = None
        self._transformRounds = None
        self._encryptIV = None
        self._streamKey = None
        self._startBytes = None
        self._innerStreamId = None
        self._kdfParams = None
        self._customData = None

    def load(self, fileHandle, fieldSize):
        bId = None
        if fieldSize == 2:
            fieldFmt = 'H'
        elif fieldSize == 4:
            fieldFmt = 'I'

        while bId != HeaderField.END:
            bId = ord(struct.unpack('c', fileHandle.read(1))[0])
            bId = HeaderField(bId)
            print(bId)
            wSize = int(struct.unpack(fieldFmt, fileHandle.read(fieldSize))[0])
            bData = fileHandle.read(wSize)

            if bId == HeaderField.END:
                # End of header
                break
            elif bId == HeaderField.COMMENT:
                continue
            elif bId == HeaderField.CIPHERID:
                self.cipherId = CipherId(int(bData.hex(), base=16))
            elif bId == HeaderField.COMPRESSION:
                self.isCompressed = bool(int.from_bytes(bData,
                                                        byteorder='little'))
            elif bId == HeaderField.MASTERSEED:
                self.masterSeed = bData
            elif bId == HeaderField.TRANSFORMSEED:
                self.transformSeed = bData
            elif bId == HeaderField.ROUNDS:
                self.transformRounds = int.from_bytes(bData,
                                                      byteorder='little')
            elif bId == HeaderField.ENCRYPTIONIV:
                self.encryptIV = bData
            elif bId == HeaderField.STREAMKEY:
                self.streamKey = bData
            elif bId == HeaderField.STARTBYTES:
                self.startBytes = bData
            elif bId == HeaderField.INNERSTREAMID:
                self.innerStreamId = int.from_bytes(bData, byteorder='little')
            elif bId == HeaderField.KDFPARAMS:
                self.kdfParams = bData
                print("kdfParams")
                # TODO: Parse KDF params
            elif bId == HeaderField.CUSTOMDATA:
                self.customData = bData
            else:
                # Error
                print("Error parsing database header!")
                break

    # TODO: Fill out properties
    @property
    def majorVersion(self):
        return self._majorVersion

    @majorVersion.setter
    def majorVersion(self, value):
        self._majorVersion = value

    @property
    def minorVersion(self):
        return self._minorVersion

    @minorVersion.setter
    def minorVersion(self, value):
        self._minorVersion = value

    @property
    def cipherId(self):
        return self._cipherId

    @cipherId.setter
    def cipherId(self, value):
        self._cipherId = value

    @property
    def isCompressed(self):
        return self._isCompressed

    @isCompressed.setter
    def isCompressed(self, value):
        self._isCompressed = bool(value)

    @property
    def masterSeed(self):
        return self._masterSeed

    @masterSeed.setter
    def masterSeed(self, value):
        self._masterSeed = value

    @property
    def transformSeed(self):
        return self._transformSeed

    @transformSeed.setter
    def transformSeed(self, value):
        self._transformSeed = value

    @property
    def transformRounds(self):
        return self._transformRounds

    @transformRounds.setter
    def transformRounds(self, value):
        self._transformRounds = value

    @property
    def encryptIV(self):
        return self._encryptIV

    @encryptIV.setter
    def encryptIV(self, value):
        self._encryptIV = value

    @property
    def streamKey(self):
        return self._streamKey

    @streamKey.setter
    def streamKey(self, value):
        self._streamKey = value

    @property
    def startBytes(self):
        return self._startBytes

    @startBytes.setter
    def startBytes(self, value):
        self._startBytes = value

    @property
    def innerStreamId(self):
        return self._innerStreamId

    @innerStreamId.setter
    def innerStreamId(self, value):
        self._innerStreamId = value

    @property
    def kdfParams(self):
        return self._kdfParams

    @kdfParams.setter
    def kdfParams(self, value):
        self._kdfParams = value

    @property
    def customData(self):
        return self._customData

    @customData.setter
    def customData(self, value):
        self._customData = value


class Kdbx:
    sig1 = 0x9aa2d903
    sig2 = 0xb54bfb67

    def __init__(self):
        self._header = KdbxHeader()
        self._compositeKey = None
        self._payload = None

    @property
    def header(self):
        return self._header

    @header.setter
    def header(self, value):
        self._header = value

    @property
    def compositeKey(self):
        return self._compositeKey

    @compositeKey.setter
    def compositeKey(self, value):
        self._compositeKey = value

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, value):
        self._payload = value


class Kdbx3(Kdbx):
    headerFieldSize = 2

    def __init__(self):
        super().__init__()

    def _decryptPayload(self, encPayload):
        key = self.header.transformSeed
        cipher = AES.new(key, AES.MODE_ECB)
        transformKey = self.compositeKey
        for _ in range(self.header.transformRounds):
            transformKey = cipher.encrypt(transformKey)
        transformKey = sha256(transformKey).digest()
        masterKey = sha256(self.header.masterSeed+transformKey)

        if self.header.cipherId == CipherId.AES128:
            print("AES128 cipher not implemented.")
            return None
        elif self.header.cipherId == CipherId.AES256:
            context = AES.new(masterKey.digest(),
                              AES.MODE_CBC,
                              iv=self.header.encryptIV)
            decPayload = context.decrypt(encPayload)
            numStartBytes = len(self.header.startBytes)
            if decPayload[:numStartBytes] == self.header.startBytes:
                return decPayload
            else:
                # Failed to properly decrypt
                return None
        elif self.header.cipherId == CipherID.CHACHA20:
            print("ChaCha20!")

    def _decompressPayload(self, gzipPayload):
        offset = 0
        blocks = b''
        while offset < len(gzipPayload):
            blockId = int.from_bytes(gzipPayload[offset:offset+4],
                                     byteorder='little')
            offset += 4
            sHash = gzipPayload[offset:offset+32]
            offset += 32
            blockSize = int.from_bytes(gzipPayload[offset:offset+4],
                                       byteorder='little')
            offset += 4
            blockData = gzipPayload[offset:offset+blockSize]
            offset += blockSize
            if blockSize == 0 and sHash == b'\x00'*32:
                break

            if sHash != sha256(blockData).digest():
                print("Block hash check failed!")
                continue

            if self.header.isCompressed:
                wbits = zlib.MAX_WBITS | 16  # gzip format
                blockData = zlib.decompress(blockData, wbits=wbits)

            blocks += blockData
        return blocks

    def load(self, fileHandle):
        encPayload = fileHandle.read()
        payload = self._decryptPayload(encPayload)

        if payload:
            payload = payload[len(self.header.startBytes):]
        else:
            print("Failed to decrypt database!")
            payload = None
            return

        if self.header.isCompressed:
            self.payload = self._decompressPayload(payload)

        self.xml = ET.fromstring(self.payload)


class Kdbx4(Kdbx):
    headerFieldSize = 4

    def __init__(self):
        super().__init__()

    def load(self, fileHandle):
        print("Kdbx4 not implemented!")
        pass
