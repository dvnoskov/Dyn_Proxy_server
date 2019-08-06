from requests.auth import HTTPBasicAuth
import requests
import json
import requests
from config import route_DB,time_update_DNS,host_DNS2,log_admin,pas_admin,host_DNS

#url = "https://members.dyndns.org/nic/update"
url = "http://members.dyndns.org/nic/update"
#url = 'http://checkip.dyndns.com'


data = {
            "hostname" : 'test.dnsalias.com',
            "myip"     : '90.99.98.166',
             "wildcard": 'NOCHG',
             "mx"      : 'NOCHG',
             "backmx"  : 'NO'
        }

data1 = {
            "hostname" : 'kik01.kiksecur.com',
            "myip"     : '192.168.1.151',
             "wildcard": 'NOCHG',
             "mx"      : 'NOCHG',
             "backmx"  : 'NO'
        }

#url="http://localhost/nic/update"
#url="http://localhost/nic/test"  #

update={'test.dnsalias.com':'90.88.98.189',
        'test.dnsalias.org':'100.68.80.90'}

update1={'kik01.kiksecur.com':'10.10.10.189',
        'kik02.kiksecur.com':'10.10.10.90'}
update2={'kik01.kiksecur.com':'1.1.1.1',
        'kik02.kiksecur.com':'1.1.1.2',
         'test.dn.net':'1.1.1.3',
         'kik03.kiksecur.com':'1.1.1.3',
         'kik04.kiksecur.com':'1.1.1.4',
         'kik05.kiksecur.com':'1.1.1.5',
         'kik06.kiksecur.com':'1.1.1.6',
        }
#r = requests.get(url,data=data,auth=("test","test"))
r = requests.get(url,params=data1,auth=("KiK","12345KiK"))
#r = requests.get(url,data=data1,auth=("KiK","12345KiK"))

#r = requests.get(url,data=json.dumps(update2),auth=(log_admin, pas_admin)) #

#url = 'http://' + host_DNS2 + '/nic/test'
#url = 'http://' + host_DNS + '/nic/test'

#r=requests.get(url, auth=(log_admin, pas_admin))
#r = requests.get(url,auth=("test","test"))
print("status_code ",r.status_code )
print(r.text)
#print(requests.ConnectionError)
#print(r.request.body)
#print(r.headers)

""""
test.dyndns.org
test.ath.cx
test.dnsalias.net
test.dnsalias.org
test.dnsalias.com
test.homeip.net
test.mine.nu
test.merseine.nu
"""
