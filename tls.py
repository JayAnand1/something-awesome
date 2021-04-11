from scapy.all import *
import sys
import json   
import argparse
import os
import csv

CLIENT_HELLO = 0x1
SERVER_HELLO = 0x2

cipher_suites = {}

def check_tls_version(packet, mapping):
    pkt_bytes = raw(packet['Raw'].load)
    version = (pkt_bytes[9] << 8) | pkt_bytes[10]
    if version == 0x0303:
        mapping['v1.2'] += 1
    if version == 0x0302:
        mapping['v1.1'] += 1
    if version == 0x0301:
        mapping['v1.0'] += 1

def setup_cipher_suites():

    with open('ciphersuites.json', 'r') as file:
        ciphersuites_json = file.read()

    ciphersuites = json.loads(ciphersuites_json)
    ciphersuites = ciphersuites['ciphersuites']

    for item in ciphersuites:
        cipher = {}
        
        name = list(item.keys())[0]
        details = item[name]

        byte_1 = int(details['hex_byte_1'],16) << 8
        byte_2 = int(details['hex_byte_2'],16)
        hex_code = byte_1 | byte_2
        
        cipher['name'] = name
        cipher['security'] = details['security']

        cipher_suites[hex_code] = cipher

def get_ciphersuites(packet):
    result = [0,0,0,0]
    ciphersuites = get_ciphersuite_hex_vals(packet)
    for cipher in ciphersuites:
        try:
            if cipher_suites[cipher]['security'] == "insecure":
                result[0] += 1
            if cipher_suites[cipher]['security'] == "weak":
                result[1] += 1
            if cipher_suites[cipher]['security'] == "secure":
                result[2] += 1
            if cipher_suites[cipher]['security'] == "recommended":
                result[3] += 1
        except KeyError as e:
            print(e)
            continue
    
    return result


def get_ciphersuite_hex_vals(packet):
    pkt_bytes = raw(packet['Raw'].load)
    try:
        session_id_offset = 43
        session_id_length = pkt_bytes[session_id_offset]
        cipher_suites_length_bytes = pkt_bytes[(session_id_offset + session_id_length + 1) : (2 + session_id_offset + session_id_length + 1)]

        cipher_suites_length = cipher_suites_length_bytes[0] << 8 | cipher_suites_length_bytes[1]
        start = 2 + session_id_offset + session_id_length + 1 + 1

        data = pkt_bytes[start : start + cipher_suites_length]
        cipher_vals = []
        for i in range(0,len(data),2):
            hex_code = (data[i]) | data[i + 1] << 8
            cipher_vals.append(hex_code)
    except IndexError as e:
        print(e)
        return []
    return cipher_vals

def tls_handshake_type(packet):
    pkt_bytes = raw(packet['Raw'].load)
    return pkt_bytes[5]

def tls_handshake(packet):
    pkt_bytes = raw(packet['Raw'].load)
    return pkt_bytes[0] == 0x16

def get_negotiated_cipher(packet):
    try:
        pkt_bytes = raw(packet['Raw'].load)
        session_id_offset = 43
        session_id_length = pkt_bytes[session_id_offset]
        
        cipher_suite_bytes = pkt_bytes[(session_id_offset + session_id_length + 1) : (2 + session_id_offset + session_id_length + 1)]
        cipher_suite = (cipher_suite_bytes[0] << 8) | cipher_suite_bytes[1]
    except IndexError as e:
        return None
    return cipher_suite


def process_pcap(file_name, json_name):

    print('Opening {}...'.format(file_name))

    devices = {}
    count = 0

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        
        count += 1
        print(count)

        ether_pkt = Ether(pkt_data)

        try:
            if not (ether_pkt[TCP].dport == 443 or ether_pkt[TCP].sport == 443):
                continue
            if not tls_handshake(ether_pkt):
                continue
        except (KeyError,IndexError) as e:
            print(e)
            continue

        handshake = tls_handshake_type(ether_pkt)

        if handshake == CLIENT_HELLO:
            
            key = ether_pkt.src

            if key not in devices:
                device = {}
                device['mac'] = key
                device['ip'] = ether_pkt[IP].src
                device['version'] = {}
                device['version']['v1.0'] = 0
                device['version']['v1.1'] = 0
                device['version']['v1.2'] = 0

                check_tls_version(ether_pkt, device['version'])
                
                ciphers_offered = get_ciphersuites(ether_pkt)
                
                device['ciphers_offered'] = {}
                device['ciphers_offered']['insecure'] = ciphers_offered[0]
                device['ciphers_offered']['weak'] = ciphers_offered[1]
                device['ciphers_offered']['secure'] = ciphers_offered[2]
                device['ciphers_offered']['recommended'] = ciphers_offered[3]
                

                device['unsafe_cipher_details'] = []
                
                for cipher in get_ciphersuite_hex_vals(ether_pkt):
                    try:
                        if cipher_suites[cipher]['security'] == 'insecure' or cipher_suites[cipher]['security'] == 'weak':
                            device['unsafe_cipher_details'].append(cipher_suites[cipher])
                    except KeyError as e:
                        print(e)
                        continue

                device['ciphers_accepted'] = {}
                device['ciphers_accepted']['insecure'] = 0
                device['ciphers_accepted']['weak'] = 0
                device['ciphers_accepted']['secure'] = 0
                device['ciphers_accepted']['recommended'] = 0

                devices[key] = device
            
            else:
                check_tls_version(ether_pkt, devices[key]['version'])

                ciphers_offered = get_ciphersuites(ether_pkt)
                
                devices[key]['ciphers_offered']['insecure'] += ciphers_offered[0]
                devices[key]['ciphers_offered']['weak'] += ciphers_offered[1]
                devices[key]['ciphers_offered']['secure'] += ciphers_offered[2]
                devices[key]['ciphers_offered']['recommended'] += ciphers_offered[3]
        
        elif handshake == SERVER_HELLO:
            
            key = ether_pkt.dst

            cipher_suite = get_negotiated_cipher(ether_pkt)
            if cipher_suite is None:
                continue
                        
            try:
                if cipher_suites[cipher_suite]['security'] == 'insecure':
                    devices[key]['ciphers_accepted']['insecure'] += 1
                    if cipher_suites[cipher_suite] not in devices[key]['unsafe_cipher_details']:
                        devices[key]['unsafe_cipher_details'].append(cipher_suites[cipher_suite])
                if cipher_suites[cipher_suite]['security'] == 'weak':
                    devices[key]['ciphers_accepted']['weak'] += 1
                    if cipher_suites[cipher_suite] not in devices[key]['unsafe_cipher_details']:
                        devices[key]['unsafe_cipher_details'].append(cipher_suites[cipher_suite])
                if cipher_suites[cipher_suite]['security'] == 'secure':
                    devices[key]['ciphers_accepted']['secure'] += 1
                if cipher_suites[cipher_suite]['security'] == 'recommended':
                    devices[key]['ciphers_accepted']['recommended'] += 1
            except KeyError as e:
                devices[key]['ciphers_accepted']['insecure'] += 1
        else:
            continue

    
    devices_list = list(devices.values())

    with open(json_name, 'w', encoding='utf-8') as f:
        json.dump({
        'devices' : devices_list
    }, f, ensure_ascii=False, indent=4)

    print('Writing to {}...'.format(json_name))


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    
    args = parser.parse_args()
    file_name = args.pcap
    json_name = args.pcap.split('/')[-1].split('.pcap')[0] + ".json"

    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    setup_cipher_suites()
    
    process_pcap(file_name, json_name)
    
    sys.exit(0)