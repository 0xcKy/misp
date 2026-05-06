from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
import argparse
from collections import defaultdict

parser = argparse.ArgumentParser() #create parser
parser.add_argument("-i", "--id", type=str, help="pulse id") #add pulse id argument
parser.add_argument("-o", "--output", type=str, help="output file") #add output file argument
argument = parser.parse_args()

otx = OTXv2("<OTX_API_key>")
ioc_result = defaultdict(list)
filename = argument.output
# Get all the indicators associated with a pulse
pulses = otx.get_pulse_indicators(argument.id)

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

def get_pulses():
        for indicator in pulses:
                ioc = indicator['indicator']
                ioc_type = indicator['type']
                ioc_type = type_mapping.get(ioc_type, ioc_type)
                ioc_result[ioc_type].append(ioc)
            
def write_file(i):
        with open(str(filename), 'a+') as f:
                f.seek(0)
                exist = set(line.strip() for line in f)
                new = set(i) - exist
                f.seek(0,2)
                for items in sorted(new):
                        f.write('%s\n' %items)


if __name__ == "__main__":
        get_pulses()
        if (filename):
                result_list = []
                for ioc_type, ioc in ioc_result.items():
                        for iocs in ioc:
                                result_list.append(ioc_type+":"+iocs)
                write_file(result_list)
