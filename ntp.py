from scapy.all import *
import sys
import json   
import argparse
import os
import csv

CLIENT_INIT = '146.156.146.168'
SUBNET = '192.168.1'

SYMMETRIC_PASSIVE = 1
SYMMETRIC_ACTIVE = 2
CLIENT_MODE = 3
SERVER_MODE = 4
BROADCAST_MODE = 5
RESERVED_MODE_1 = 6
RESERVED_MODE_2 = 7

NTP_EPOCH = 2208988800

UNSYNCHRONIZED = 3

HALF_DAY = 43200

def get_ip_version(pkt):
    if 'IPv6' in pkt:
        return 'IPv6'
    else:
        return 'IP'

def ntp_request(packet):
    packet.show()
    return packet[IP].src[:9] == SUBNET

def is_client_server(packet):
    if packet[IP].src[:9] == SUBNET and packet['NTPHeader'].mode == SERVER_MODE:
        return 1
    return 0

def latest_version(packet):
    if packet['NTPHeader'].version == 4:
        return 1
    return 0

# def leap_indicator_warning(packet):
#     if packet['NTPHeader'].leap == UNSYNCHRONIZED:
#         return 1
#     return 0

def reserved_mode(packet):
    if packet['NTPHeader'].mode == RESERVED_MODE_1 or packet['NTPHeader'].mode == RESERVED_MODE_2:
        return 1
    return 0

def symmetric_mode(packet):
    if packet['NTPHeader'].mode == SYMMETRIC_ACTIVE or packet['NTPHeader'].mode == SYMMETRIC_PASSIVE:
        return 1
    return 0

def incorrect_mode(packet):
    if packet['NTPHeader'].mode == 0 or packet['NTPHeader'].mode > 7:
        return 1
    return 0

def broadcast_mode(packet):
    if packet[IP].dst[:9] == SUBNET and packet['NTPHeader'].mode == BROADCAST_MODE:
        return 1
    return 0

def accepting_broadcast(packet):
    if packet[IP].dst[:9] == SUBNET and packet['NTPHeader'].mode == 5:
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
            if 'NTP' not in ether_pkt:
                continue  
        except (IndexError, UnicodeDecodeError, AttributeError) as e:
            print(e)
            continue
        
        if ntp_request(ether_pkt):
            key = ether_pkt.src

    
            if key in devices:
                devices[key]['is_client_server'] += is_client_server(ether_pkt)
                devices[key]['latest_version'] += latest_version(ether_pkt)
                devices[key]['mode']['reserved'] += reserved_mode(ether_pkt)
                devices[key]['mode']['symmetric'] += symmetric_mode(ether_pkt)
                devices[key]['mode']['invalid'] += incorrect_mode(ether_pkt)
                devices[key]['mode']['broadcast'] += broadcast_mode(ether_pkt)
                devices[key]['accepting_broadcast'] = accepting_broadcast(ether_pkt)
                devices[key]['exchanges'] += 1
            else:
                device = {}
                device['ip'] = ether_pkt[get_ip_version(ether_pkt)].src
                device['mac'] = ether_pkt.src
                device['is_client_server'] = is_client_server(ether_pkt)
                device['latest_version'] = latest_version(ether_pkt)
                device['mode'] = {}
                device['mode']['reserved'] = reserved_mode(ether_pkt)
                device['mode']['symmetric'] = symmetric_mode(ether_pkt)
                device['mode']['invalid'] = incorrect_mode(ether_pkt)
                device['mode']['broadcast'] = broadcast_mode(ether_pkt)
                device['accepting_broadcast'] = accepting_broadcast(ether_pkt)
                device['exchanges'] = 1
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
    
    args = parser.parse_args()
    file_name = args.pcap
    json_name = args.pcap.split('/')[-1].split('.pcap')[0] + ".json"
    
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)
    
    process_pcap(file_name, json_name)
    
    sys.exit(0)
        




