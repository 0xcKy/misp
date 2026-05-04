from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
otx = OTXv2("OTX_API")
result_list = []

# Get all the indicators associated with a pulse
pulses = otx.get_pulse_indicators("pulse_ID")

#map otx attribute types, and replace to MISP equivalent (will be used later to add events)
type_mapping = {
    'FileHash-MD5': 'md5',
    'FileHash-SHA1': 'sha1',
    'FileHash-SHA256': 'sha256',
    'FileHash-SHA512': 'sha512',
    'BitcoinAddress': 'btc',
    'URL': 'url',
    'CVE': 'vulnerability',
    'IPv4': 'ip-src',
    'YARA': 'comment',
    'SSLCertFingerprint': 'comment'
}

for indicator in pulses:
        ioc = indicator['indicator']
        ioc_type = indicator['type']
        #replace the ioc_type using the mapping
        ioc_type = type_mapping.get(ioc_type, ioc_type)
        result_list.append(ioc + " " + ioc_type)

print (result_list)
