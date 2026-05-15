#!/usr/bin/python

from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from pprint import pprint
from collections import defaultdict
from pymisp import PyMISP
import argparse

parser = argparse.ArgumentParser() #create parser
exclusive = parser.add_mutually_exclusive_group()
exclusive.add_argument("-e", "--event", action="store_true", help="create MISP event") #create misp event
argument = parser.parse_args()

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

# Get all the indicators associated subscribed pulses
def get_all_misp_create():
        pulses_json = otx.getall()
        for pulses in pulses_json:
                event_info["adversary"] = pulses['adversary']
                event_info["description"] = pulses ['description']
                event_info["industries"] = pulses ['industries']
                event_info["name"] = pulses['name']
                event_info["references"] = pulses['references']
                event_info["targeted_countries"] = pulses['targeted_countries']
                event_info["malware_families"] = pulses['malware_families']
                event_info["tags"] = pulses['tags']
                event_info["attack_ids"] = pulses['attack_ids']
                indicators = pulses['indicators']
                for i in indicators:
                        ioc = i['indicator']
                        ioc_type = i['type']
                        ioc_type = type_mapping.get(ioc_type, ioc_type)
                        ioc_result[ioc_type].append(ioc)
                        ioc_result[ioc_type].append(ioc)
                create_event()
def create_event():
        misp = PyMISP(MISP_URL, MISP_KEY, ssl=False, debug=False) #remember to use SSL on production instances
        event = MISPEvent()
        event.info = event_info["name"]
        event.analysis = "2" #completed
        event.published = False
        event.distribution = "0" #your org only
        event.threat_level_id = "2" #level HIGH
        #adding attributes to event
        event.add_attribute('link', event_info["references"], disable_correlaction=False)
        event.add_attribute('comment', event_info["description"], disable_correlaction=False)
        for ioc_type, ioc in ioc_result.items():
                for i in ioc:
                        event.add_attribute(ioc_type, ioc, disable_correlaction=False)
        #adding tags to event
        #IMPORTANT: the authkey user needs the 'Tag Editor' permission, otherwise we'll not be able create custom tags
        event.add_tag('tlp:clear')
        if event_info["targeted_countries"]:
                for tags in event_info["targeted_countries"]:
                        event.add_tag('targeted_countries:'+event_info["targeted_countries"])
        if event_info["industries"]:
                for tags in event_info["industries"]:
                        event.add_tag('industries:'+event_info["industries"])
        for tags in event_info["tags"]:
                event.add_tag(tags)
        for tags in event_info["attack_ids"]:
                event.add_tag(tags)
        for tags in event_info["malware_families"]:
                event.add_tag(tags)
        if event_info["adversary"]:
               event.add_tag('adversary:'+event_info["adversary"])
        #creating event
        event = misp.add_event(event)
        print("[+]Event '"+event_info["name"]+"' created!")

if __name__ == "__main__":
        event_info = {}
        ioc_result = defaultdict(list)
        if (argument.event):
                get_all_misp_create()
        else:
                print("Missing arguments -e. Use -h for help.")
