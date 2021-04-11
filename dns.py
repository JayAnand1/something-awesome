from scapy.all import *
import sys
import json   
import argparse
import os
import csv


def dnssec_enabled(dns_pkt):
    if dns_pkt.ar is None:
        return 0
    if hex(dns_pkt.ar.z == 0x8000):
        return 1
    return 0

def get_ip_version(pkt):
    if 'IPv6' in pkt:
        return 'IPv6'
    else:
        return 'IP'

def dns_query(dns_pkt):
    '''
    Check if DNS packet is query request
    '''   
    return dns_pkt.qr == 0

def dns_response(dns_pkt):
    '''
    Check if DNS packet is query response
    '''   
    return dns_pkt.qr == 1

def q_type_any_flag(dns_pkt):
    '''
    See if the q-type field in a query
    are set to * or ANY. Risk of relfection attack
    '''
    total = 0
    for i in range(dns_pkt.qdcount):
        try:
            if dns_pkt['DNSQR'][i].qtype == 255:
                total += 1
        except KeyError as e:
            continue
    return total

def q_class_any_flag(dns_pkt):
    '''
    See if the q-class field in a query
    are set to * or ANY. Risk of relfection attack
    '''
    total = 0
    for i in range(dns_pkt.qdcount):
        try:
            if dns_pkt['DNSQR'][i].qclass == 255:
                total += 1
        except KeyError as e:
            continue
    return total


def RRSIG_received(dns_packet):
    '''
    Check if hostname is dnssec secure
    '''
    if dns_packet.ancount > 0  and 'DNS RRSIG Resource Record' in dns_packet.an:
        return True
    return False

def check_dnnsec_algorithm(dns_packet):
    '''
    Check that packet uses RSA/SHA-1 (mandatory).
    All other algoritms are optional or not
    recommended. 
    Check - https://tools.ietf.org/html/rfc4034#appendix-A.1
    '''
    if dns_packet.ancount > 0 and dns_packet.an['DNS RRSIG Resource Record'].algorithm == 5:
        return 1
    return 0


def process_pcap(file_name, json_name):

    print('Opening {}...'.format(file_name))

    devices = {}
    count = 0

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        
        count += 1
        print(count)
        try:
            ether_pkt = Ether(pkt_data)
            if DNS not in ether_pkt:
                continue
            dns_pkt = ether_pkt[DNS]
  
        except (IndexError, UnicodeDecodeError, AttributeError) as e:
            print(e)
            continue
        
        if dns_query(dns_pkt):
            key = ether_pkt.src

            dnssec = dnssec_enabled(dns_pkt)
            q_type = q_type_any_flag(dns_pkt)
            q_class = q_class_any_flag(dns_pkt)

            if key in devices:
                devices[key]['dnssec_enabled'] += dnssec
                devices[key]['q_type_any'] += q_type
                devices[key]['q_class_any'] += q_class
                devices[key]['exchanges'] += 1
            else:
                device = {}
                device['ip'] = ether_pkt[get_ip_version(ether_pkt)].src
                device['mac'] = ether_pkt.src
                device['q_type_any'] = q_type
                device['q_class_any'] = q_class
                device['exchanges'] = 1
                device['RRSIG'] = 0
                device['dnssec_algo'] = 0
                device['dnssec_enabled'] = dnssec
                devices[key] = device
        
        if dns_response(dns_pkt):
            key = ether_pkt.dst
            
            dnssec = 0
            dnssec_algo = 0
            
            if RRSIG_received(dns_pkt):
                dnssec = 1
                dnssec_algo = check_dnnsec_algorithm(dns_pkt)
                try: 
                    devices[key]['RRSIG'] += dnssec
                    devices[key]['dnssec_algo'] += dnssec_algo
                except KeyError as e:
                    print(e)

                


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
    
    process_pcap(file_name, json_name)
    
    sys.exit(0)
        

