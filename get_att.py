from pymisp import PyMISP
from pprint import pprint

MISP_URL = '<MISP_DOMAIN>'
MISP_KEY = '<MISP_AUTH_KEY>'
id = int(input("Event ID:\n"))
misp = PyMISP(MISP_URL, MISP_KEY, ssl=False, debug=False) #create misp instance, uses URL and KEY, disable ssl and debug
response = misp.search(return_format='json', controller='attributes', eventid=id, type_attribute=['ip-src','ip-dst'], to_ids=1) #uses search to return attributes using ID, type and IDS only
values = [attr.get("value") for attr in response.get("Attribute", [])] #get json from response and separete 'values'

with open('ip_list_export.txt', 'a+') as f: #open file
    for items in values: #write elements of list
        f.write('%s\n' %items)
    print("File written successfully")

f.close() #closes file
