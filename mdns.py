from scapy.all import *
import sys
import json   
import argparse
import os

TXT = 0x10
PTR = 0xc
A_REC = 0x1
AAAA_REC = 0x1c
RESPONSE = 1
QUERY = 0

def dns_response(dns_pkt):
    return dns_pkt.qr == RESPONSE

def dns_query(dns_pkt):
    return dns_pkt.qr == QUERY


def get_txt_record(dns_pkt):
    details = []
    for i in range(dns_pkt.ancount + dns_pkt.arcount):
        try: 
            if dns_pkt['DNSRR'][i].type == TXT or dns_pkt['DNSRR'][i].type == PTR or dns_pkt['DNSRR'][i].type == A_REC or dns_pkt['DNSRR'][i].type == AAAA_REC:
                details.append(dns_pkt['DNSRR'][i].rrname.decode('utf-8'))
                if type(dns_pkt['DNSRR'][i].rdata) == str:
                    details.append(dns_pkt['DNSRR'][i].rdata)
                elif type(dns_pkt['DNSRR'][i].rdata) == bytes:
                    details.append(dns_pkt['DNSRR'][i].rdata.decode('utf-8'))
                else:
                    for item in dns_pkt['DNSRR'][i].rdata:
                        detail = item.decode('utf-8') if type(item) == bytes else item
                        if type(detail) != int and len(detail) > 1:   
                            details.append(detail)
        except (IndexError,UnicodeDecodeError, AttributeError) as e:
            print(e)
    
    return list(set(details))

def get_ip_version(ip_pkt):
    if ip_pkt.version == 6:
        return 'IPv6'
    else:
        return 'IP'

def process_pcap(file_name, json_name):

    print('Opening {}...'.format(file_name))

    devices = {}
    count = 0

    
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):

        count += 1
        print(count)
        try:
            ether_pkt = Ether(pkt_data)
            ip_pkt = ether_pkt[IP]
            dns_pkt = ip_pkt[DNS]
        except (IndexError, UnicodeDecodeError, AttributeError) as e:
            print('Possible malformed or non mDNS packet')
            continue

        key = ether_pkt.src
        
        if key in devices:
            if dns_response(dns_pkt):
                devices[key]['details'] = devices[key]['details'] + get_txt_record(dns_pkt)
                devices[key]['details'] = list(set(devices[key]['details']))
            devices[key]['packet_count'] += 1
        else:
            device = {}
            device['mac'] = ether_pkt.src
            device['ip'] =  ip_pkt.src
            device['packet_count'] = 1
            device['details'] = get_txt_record(dns_pkt) if dns_response(dns_pkt) else []
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