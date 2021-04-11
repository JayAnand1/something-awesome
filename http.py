from scapy.all import *
import sys
import json   
import argparse
import os

def form_to_dict(packet):
    form_dict = {}
    try:
        form = packet['Raw'].load.decode('utf-8')
        
        pairs = form.split('%')[0].split('&')

        for pair in pairs:
            key, val = pair.split('=')[0], pair.split('=')[1]
            form_dict[key] = val
    except (IndexError, UnicodeDecodeError, AttributeError) as e:
        print(e)
        return None
    return form_dict

def auth_to_dict(http_headers):
    auth_dict = {}
    try:
        auth = http_headers.Authorization.decode('utf-8')
        pairs = auth.split(',')
        for pair in pairs:
            key, val = pair.split('=',1)[0].strip(), pair.split('=',1)[1].strip('"')
            auth_dict[key] = val
        auth_dict['uri'] = http_headers.Path.decode('utf-8')
        auth_dict['method'] = http_headers.Method.decode('utf-8')
    except (IndexError, UnicodeDecodeError, AttributeError) as e:
        print(e)
        return None

    return auth_dict

def process_pcap(file_name, json_name):

    print('Opening {}...'.format(file_name))

    devices = {}
    count = 0

    load_layer("http")

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count+=1
        try:
            ether_pkt = Ether(pkt_data)
            if not 'HTTP Request' in ether_pkt:
                continue
        except (IndexError, UnicodeDecodeError, AttributeError) as e:
            print(e)
            continue
        
        
        key = ether_pkt.src
        http_header = ether_pkt['HTTP Request']
        try: 
            if key in devices:
                digest_auth = auth_to_dict(http_header)
                if digest_auth is not None:
                    devices[key]['vulnerabilities'].append(digest_auth)
                form = form_to_dict(ether_pkt)
                if form is not None:
                    devices[key]['vulnerabilities'].append(form)
            else:
                device = {}
                device['ip'] = ether_pkt[IP].src
                device['mac'] = key
                
                device['user_agent'] = http_header.User_Agent.decode('utf-8')
                device['vulnerabilities'] = []
                digest_auth = auth_to_dict(http_header)
                if digest_auth is not None:
                    devices[key]['vulnerabilities'].append(digest_auth)
                form = form_to_dict(ether_pkt)
                if form is not None:
                    devices[key]['vulnerabilities'].append(form)
                devices[key] = device
        except (IndexError, UnicodeDecodeError, AttributeError) as e:
            print(e)
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
    json_name = args.pcap.split('/')[-1].split('.pcap')[0] + '.json'
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name, json_name)
    sys.exit(0)
