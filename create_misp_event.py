#!/usr/bin/python

from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from pprint import pprint
from collections import defaultdict
from pymisp import PyMISP
import argparse
import json

parser = argparse.ArgumentParser() #create parser
exclusive = parser.add_mutually_exclusive_group()
exclusive.add_argument("-a", "--all", action="store_true", help="download all subscribed pulses")
exclusive.add_argument("-e", "--event", action="store_true", help="pulse id") #add pulse id argument
exclusive.add_argument("-p", "--pulse", type=str, help="pulse id") #add pulse id argument
parser.add_argument("-o", "--output", type=str, help="output file") #add output file argument
parser.add_argument("-s", "--screen", action="store_true", help="show output on screen") #add output to screen
argument = parser.parse_args()

filename = argument.output
screen = argument.screen
otx = OTXv2("<OTX_API_KEY>")
MISP_URL = '<MISP_DOMAIN>'
MISP_KEY = '<MISP_AUTH_KEY>'
type_mapping = {
        'BitcoinAddress': 'btc',
        'CIDR': 'comment',
        'CVE': 'vulnerability',
        'Domain': 'domain',
        'Email': 'email',
        'FileHash-IMPHASH': 'imphash',
        'FileHash-MD5': 'md5',
        'FileHash-PEHASH': 'pehash',
        'FileHash-SHA1': 'sha1',
        'FileHash-SHA256': 'sha256',
        'FileHash-SHA512': 'sha512',
        'Hostname': 'hostname',
        'IPv4': 'ip-src',
        'IPv6': 'ip-src',
        'Mutex': 'mutex',
        'NIDS': 'comment',
        'Osquery': 'comment',
        'SSLCertFingerprint': 'comment',
        'URI': 'uri',
        'URL': 'url',
        'YARA': 'comment',
        'YARA': 'yara'
}

# Get all the indicators associated with a pulse
def get_pulses():
        pulses = otx.get_pulse_indicators(argument.pulse)
        for indicator in pulses:
                ioc = indicator['indicator']
                ioc_type = indicator['type']
                ioc_type = type_mapping.get(ioc_type, ioc_type)
                ioc_result[ioc_type].append(ioc)
# Get all the indicators associated with subscribed pulses
def get_all():
        pulses_json = otx.getall()
        pprint(pulses_json)
        for pulses in pulses_json:
                indicators = pulses['indicators']
                for i in indicators:
                        ioc = i['indicator']
                        ioc_type = i['type']
                        ioc_type = type_mapping.get(ioc_type, ioc_type)
def create_event():
        pulses_json = otx.getall()
        for pulses in pulses_json:
                adversary = pulses['adversary']
                attack_ids = pulses['attack_ids']
                description = pulses ['description']
                indicators = pulses['indicators']
                name = pulses['name']
                references = pulses['references']
                targeted_countries = pulses['targeted_countries']
                tlp = pulses['tlp']
                for i in indicators:
                        ioc = i['indicator']
                        ioc_type = i['type']
                        ioc_type = type_mapping.get(ioc_type, ioc_type)
                        ioc_result[ioc_type].append(ioc)
                        ioc_result[ioc_type].append(ioc)
# Create or append indicators to output file
def write_file(i):
        with open(str(filename), 'a+') as f:
                f.seek(0)
                exist = set(line.strip() for line in f)
                new = set(i) - exist
                f.seek(0,2)
                for items in sorted(new):
                        f.write('%s\n' %items)
def write_screen(i):
        for line in i:
                print(line)

if __name__ == "__main__":

        ioc_result = defaultdict(list)
        result_list = []

        if (argument.all):
                get_all()
                if (filename):
                        for ioc_type, ioc in ioc_result.items():
                                for iocs in ioc:
                                        result_list.append(ioc_type+":"+iocs)
                        write_file(result_list)
                if (screen):
                        for ioc_type, ioc in ioc_result.items():
                                for iocs in ioc:
                                        result_list.append(ioc_type+":"+iocs)
                        write_screen(result_list)
        elif (argument.pulse):
                get_pulses()
                if (filename):
                        for ioc_type, ioc in ioc_result.items():
                                for iocs in ioc:
                                        result_list.append(ioc_type+":"+iocs)
                        write_file(result_list)
                if (screen):
                        for ioc_type, ioc in ioc_result.items():
                                for iocs in ioc:
                                        result_list.append(ioc_type+":"+iocs)
                        write_screen(result_list)
        elif (argument.event):
                create_event()
        else:
                print("Missing arguments -p or -a. Use -h for help.")
