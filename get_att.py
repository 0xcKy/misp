from pymisp import PyMISP
from pprint import pprint

MISP_URL = '<MISP_DOMAIN>'
MISP_KEY = '<MISP_AUTH_KEY>'
id = int(input("Event ID:\n"))
misp = PyMISP(MISP_URL, MISP_KEY, ssl=False, debug=False) #create misp instance, uses URL and KEY, disable ssl and debug
response = misp.search(return_format='json', controller='attributes', eventid=id, type_attribute=['ip-src','ip-dst'], to_ids=1) #uses search to return attributes using ID, type and IDS only
values = [attr.get("value") for attr in response.get("Attribute", [])] #get json from response and separete 'values'

with open('ip_list_export.txt', 'a+') as f: #open file
        f.seek(0)                                       #go to file beginning
        exist = set(line.strip() for line in f)         #strip f content into 'exist' var
        new = set(values) - exist                       #get 'values' content and remove 'exist' from it
        f.seek(0,2)                                     #go to file end
        for items in sorted(new):                       #write elements of list in sorted format
                f.write('%s\n' %items)
        print("File written successfully")
f.close()
