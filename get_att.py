from pymisp import PyMISP
import argparse

parser = argparse.ArgumentParser() #create parser
parser.add_argument("-e", "--eventid", action="extend", nargs="+", type=str, help="list of events to download") #add list of events
parser.add_argument("-a", "--attribute", nargs="+", help="type of attribute") #add attrib type
parser.add_argument("-o", "--outfile", type=str, help="output file name") #add attrib type
parser.add_argument("-w", "--warning", action='store_true', help="filter out attributes from warninglists") #add warninglist type
argument = parser.parse_args()

MISP_URL = '<MISP_DOMAIN>'
MISP_KEY = '<MISP_AUTH_KEY>'

id_number = argument.eventid
attrib = argument.attribute
filename = argument.outfile
warning = argument.warning
result_list = []

def get_att():
        #create misp instance, uses URL and KEY, disable ssl and debug
        misp = PyMISP(MISP_URL, MISP_KEY, ssl=False, debug=False)
        #uses search to return attributes using ID, type and IDS only
        response = misp.search(return_format='json', controller='attributes', eventid=id_number, exclude_decayed=True, type_attribute=attrib, to_ids=1, enforce_warninglist=warning)
        #get json from response and separate 'values'
        return [attr.get("value") for attr in response.get("Attribute", [])]

def write_file(i):
        with open(str(filename), 'a+') as f:
                f.seek(0)
                exist = set(line.strip() for line in f)
                new = set(i) - exist
                f.seek(0,2)
                for items in sorted(new):
                        f.write('%s\n' %items)
                print("File written successfully")
        f.close()

if __name__ == '__main__':
        if (id_number and attrib):
                result_list = get_att()
                if (filename):
                        write_file(result_list)
        else:
                print("Event ID or attribute type missing. Use -h for help")
