from scapy.all import *
import sys
import json   
import argparse
import os

NOTIFY = 'NOTIFY * HTTP/1.1'
MSEARCH = 'M-SEARCH * HTTP/1.1'
HTTP = 'HTTP/1.1 200 OK'

def get_ip_version(pkt):
    if 'IPv6' in pkt:
        return 'IPv6'
    else:
        return 'IP'

def check_ttl(pkt):
    if pkt[IP].ttl > 2:
        return 1
    return 0

def m_search_risk(pkt):
    pass


def process_pcap(file_name, json_name):

    print('Opening {}...'.format(file_name))

    devices = {}
    count = 0

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):

        try:
            ether_pkt = Ether(pkt_data)
            ip_pkt = ether_pkt[get_ip_version(ether_pkt)]
            if ether_pkt[UDP].dport != 1900 or ether_pkt[UDP].sport != 1900:
                continue
            ether_pkt.show()
            continue
        except (IndexError, UnicodeDecodeError, AttributeError) as e:
            print(e)
            continue
        
        print(count)
        count+=1

        key = ether_pkt.src
       
        message_type = get_ssdp_message_type(ssdp_headers)
  
        
        if key in devices:
            devices[key]['packet_count'] += 1
            devices[key]['details'] = devices[key]['details'] + get_ssdp_details(ssdp_headers)
            devices[key]['details'] = list(set(devices[key]['details']))     
            devices[key]['locations'] = devices[key]['locations'] + get_ssdp_location(ssdp_headers)
            devices[key]['locations'] = list(set(devices[key]['locations']))  
        else:
            device = {}
            device['packet_count'] = 1
            device['ip'] = ip_pkt.src
            device['mac'] = key
            
            device['details'] = get_ssdp_details(ssdp_headers)
            device['locations'] = get_ssdp_location(ssdp_headers)

            devices[key] = device
    
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
    parser.add_argument('--json', metavar='<json output file name>',
                        help='name for output json file', required=True)
    args = parser.parse_args()
    
    file_name = args.pcap
    json_name = args.json + '.json'
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name, json_name)
    sys.exit(0)
