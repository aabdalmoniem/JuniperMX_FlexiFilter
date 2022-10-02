#!/usr/bin/env python3

from datetime import datetime
import sys, os
import subprocess
import logging
import re
import shlex
from jinja2 import Environment, FileSystemLoader
from random import randint
import ipaddress
import argparse
import converter_func

## define logging

logging.basicConfig(
    format = '%(threadName)s %(name)s %(levelname)s: %(message)s',
    level=logging.INFO)

logging.info(' start of program')


def arguements_parser():
    """:cvar
    Required aruments are : filte name and filter type
    Optional arguemnts are : ipv4/ipv6/MAC/MPLS label/port number
    """
    parser = argparse.ArgumentParser(description='Generate FlexiFilter config for MX.')

    parser.add_argument('--name',type=str,required=True,help='Filter name')
    parser.add_argument('--filter_type',type=str,required=True,help='Filter Type (UDP/TCP/VPLS/L2VPN/MPLS')
    parser.add_argument('--ipv4',type=str,required=False,help ='IPv4 address to match')
    parser.add_argument('--ipv6',type=str,required=False,help ='IPv6 address to match')
    parser.add_argument('--mac',type=str,required=False,help ='MAC address to match')
    parser.add_argument('--port',type=int,required=False,help ='Port number to match')
    parser.add_argument('--label',type=int,required=False,help ='MPLS label to match')
    parser.add_argument('--direction', type=str, required=False, help='src/dst port to match')

    args = parser.parse_args()

    filter_name = args.name
    filter_type = args.filter_type

    if len(sys.argv) < 6:
        print("At least 3 arguments are needed")
        return

    return {'filter_name':args.name,
            'filter_type':args.filter_type,
            'ipv4':args.ipv4,
            'ipv6':args.ipv6,
            'mac':args.mac,
            'label':args.label,
            'port':args.port,
            'direction':args.direction}



def mpls_ip_payload(ipv4,src_dst):
    """:cvar
    This function return filter_seeds for MPLS matching on payload src/dst IPs
    the return goes to generate_filter() function
    """
    ffamily = 'mpls'
    bit_length = 32 ## IPv4 address length
    match_start = 'payload'
    if src_dst == 'src': #byte_offset will change depend on src == 12 /dst == 16 IP
        byte_offset = 12
    else:
        byte_offset = 16

    range_hex = converter_func.ip_4_conv(ipv4)
    return match_start,byte_offset,bit_length,range_hex,ffamily

def ipv4_udp(port_number,src_dst):
    """:cvar
    This function return filter_seeds for IPv4 UDP matching on src/dst ports
    the return goes to generate_filter() function
    """
    ffamily = 'inet'
    bit_length = 16 ## port
    match_start = 'layer-4'
    range_hex = converter_func.port_conv(port_number)
    if src_dst == 'src':
        byte_offset = 0
    else:
        byte_offset = 2
    return match_start,byte_offset,bit_length,range_hex,ffamily

def mpls_first_label(label):
    """:cvar
    This function return filter_seeds for MPLS matching on 1st label
    the return goes to generate_filter() function
    """
    ffamily = 'mpls'
    bit_length = 20 ## MPLS label size
    match_start = 'layer-3'
    byte_offset = 0
    range_hex = converter_func.mpls_label_conv(label)
    return match_start,byte_offset,bit_length,range_hex,ffamily

def mpls_second_label(label):
    """:cvar
    This function return filter_seeds for MPLS matching on 1st label
    the return goes to generate_filter() function
    """
    ffamily = 'mpls'
    bit_length = 20 ## MPLS label size
    match_start = 'layer-3'
    byte_offset = 4 ## start of 2nd label
    range_hex = converter_func.mpls_label_conv(label)
    return match_start,byte_offset,bit_length,range_hex,ffamily

def mpls_ip4_payload(ipv4,src_dst):
    """:cvar
    This function return filter_seeds for MPLS matching on payload src/dst IPs
    byte_offset will change depend on src == 12 /dst == 16 IP. bit length is 32 for the IPv4 address
    the return goes to generate_filter() function
    """
    ffamily = 'mpls'
    bit_length = 32 ## MPLS label size
    match_start = 'payload'
    if src_dst == 'src':
        byte_offset = 12
    else:
        byte_offset = 16

    range_hex = converter_func.ip_4_conv(ipv4)
    return match_start,byte_offset,bit_length,range_hex,ffamily


def evpn_payload_ip(ipv4,src_dst):
    """:cvar
    This function return filter_seeds for EVPN src/dst IP address
    the return goes to generate_filter() function
    """
    bit_length = 32 ## IPv4 size
    match_start = 'layer-4'
    if src_dst == 'src:':
        byte_offset = 42 ## start of src IP address
    else:
        byte_offset = 46  ## start of dst IP address
    range_hex = converter_func.ip_4_conv(ipv4)
    return match_start,byte_offset,bit_length,range_hex


def evpn_payload_mac(mac,src_dst):
    """:cvar
    This function return filter_seeds for EVPN src/dst IP address
    the return goes to generate_filter() function
    """
    bit_length = 48 ## MAC size
    match_start = 'layer-4'
    if src_dst == 'src:':
        byte_offset = 16 ## start of dst MAC address
    else:
        byte_offset = 22  ## start of src MAC address
    range_hex = converter_func.mac_conv(mac)
    return match_start,byte_offset,bit_length,range_hex


def mpls_ttl(label):
    """:cvar
    This function return filter_seeds for MPLS TTL
    the return goes to generate_filter() function
    """
    ffamily = 'mpls'
    bit_length = 8  ## MPLS label size
    match_start = 'layer-3'
    byte_offset = 3  ## start of 2nd label
    range_hex = converter_func.ttl_hex_converter(label)
    return match_start, byte_offset, bit_length, range_hex, ffamily


def generate_filter(filter_seeds,filter_name):
    """:cvar
    This function takes filter seeds from functions like ipv4_udp
    and it generates filter from the template
    """

    # location of templates
    ENV = Environment(loader=FileSystemLoader('.'))

    # load the template file
    template = ENV.get_template("template.j2")
    # generating config

    match_start  = filter_seeds[0]
    offset = filter_seeds[1]
    bit_length = filter_seeds[2]
    range_hex = filter_seeds[3]
    ffamily = filter_seeds[4]
    group_temp = [
        {
            "filter_name": filter_name,
            "term_name": range_hex,
            "match_start": match_start,
            "byte_offset":offset,
            "bit_length":bit_length,
            "range_hex":range_hex,
            "ffamily":ffamily
        },
    ]

    print(template.render(param_list=group_temp))



## Testing the return of arguments
args_checks = arguements_parser()

## Filtering arguement list and removing empty ones :

def args_filter():
    for k,v in dict(args_checks).items():
        if v is None:
            del args_checks[k]

#### print(args_filter(arguements_parser()))
filter_name = args_checks['filter_name']

## TCP/UDP matching generator
if args_checks['filter_type'] == 'udp' or args_checks['filter_type'] == 'tcp':
    port_number = args_checks['port']
    #filter_name = args_checks['filter_name']
    direction_test=args_checks['direction']
    filter_seeds = ipv4_udp(port_number,direction_test)
    print("This is to check the type :: ",type(filter_seeds[3]))
    generate_filter(filter_seeds,filter_name)

## MPLS label or MPLS IPv4 filter generator
if args_checks['filter_type'] == 'mpls' :
    if args_checks['direction'] =='src' or args_checks['direction'] =='dst' :
        print("this is MPLS with IPv4 payload")
        ipv4 = args_checks['ipv4']
        src_dst = args_checks['direction']
        filter_seeds = mpls_ip4_payload(ipv4,src_dst)
        print(filter_seeds)
        generate_filter(filter_seeds, filter_name)
    else:
        label = args_checks['label']
        filter_seeds = mpls_first_label(label)
        print(filter_seeds)
        print("This is to check the type :: ",type(filter_seeds[3]))
        generate_filter(filter_seeds,filter_name)

logging.info(' end of program')