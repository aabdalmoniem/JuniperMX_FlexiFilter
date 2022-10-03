#!/usr/bin/env python3
import logging
import ipaddress
import sys, os


##################################################
## Flexi Fitler generator script converter functions
##################################################
## Author: Alaa Aboeloula
## License: {license}
## Version: 1.0
## Mmaintainer: Alaa Aboeloula
## Email: aabdalmoniem@gmail.com
## Status: In progress
##################################################

logging.basicConfig(
    format = '%(threadName)s %(name)s %(levelname)s: %(message)s',
    level=logging.INFO)

## following set of functions change input (ipv4/v6/label/mac) to hexa


def port_conv(port):
    print(port, type(port))
    if port in range(0,65535):
        port_hex = hex(port)
        return port_hex
    else:
        logging.warning("Incorrect port number is given {}".format(port))


def ip_4_conv(ipv4):
    try:
        ipaddress.ip_address(ipv4) ## check if IPv4 is correct
        ip_hex = '0x'+''.join('%02X' % int(i) for i in ipv4.split('.'))
        print(ip_hex)
        return ip_hex
    except ValueError as err:
        logging.warning("Incorrect IPv4 address is given {}".format(ipv4))
        return False



def mpls_label_conv(mpls_label):
    if mpls_label in range(16,1048576):
        label_hex = '0x'+'%02X' % int(mpls_label)
        print(label_hex)
        return label_hex
    else:
        logging.warning("Incorrect MPLS label is given {}".format(mpls_label))



def ipv6_conv(ipv6):
    try:
        ipaddress.ip_address(ipv6)
        ipv6_hexa = '0x' + ''.join(ipv6.split(':'))
        print(ipv6_hexa)
        return ipv6_hexa
    except ValueError as err:
        logging.warning("Incorrect IPv6 address is given {}".format(ipv6))
        return False



def mac_conv(mac_ipv6):
    mac_hexa = '0x' + ''.join(mac_ipv6.split(':'))
    print(mac_hexa)
    return mac_hexa



def ttl_hex_converter(num):
    if num > 255 or num < 1:
        return f'{num} is not in normal TTL range 1-255'
    return hex(num)
