#!/usr/bin/python3

'''
Script which updates the address associated with a domain on NFS.N.

Originally posted here: https://www.mitsake.net/2016/04/nfsn-and-ddns-take-2/
- Modified to include syslog messages to document checks/updates
'''

from nfsn import Nfsn
import requests
import sys
import syslog

user = "<YOUR-NFSN-USER>"     # Your NFSN username
key = "<YOUR-API-KEY>"        # API key
domain = "<YOUR-NFSN-DOMAIN>" # Your NFS-hosted domain
subdomain = "<YOUR-SUBDOMAIN>" # The entry (host/subdomain) which will get your IP address

nfsn = Nfsn(user, key)        # Create the NFSN API object

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL1)
fqdn = ".".join((subdomain, domain))
syslog.syslog(syslog.LOG_INFO,
              "refreshing external IP for {}".format(fqdn))

try:
    currentip = requests.get('http://api.ipify.org').text
    listedip = nfsn.dns(domain).listRRs(subdomain)[0]['data']
    
    if currentip != listedip:
        # update required
        nfsn.dns(domain).removeRR(subdomain, 'A', listedip)
        nfsn.dns(domain).addRR(subdomain, 'A', currentip)

        syslog.syslog(syslog.LOG_INFO,
                      "record updated from {} to {} for {}".format(listedip,
                                                                   currentip,
                                                                   fqdn))
    else:
        syslog.syslog(syslog.LOG_INFO, "no update required")
except Exception as e:
    syslog.syslog(syslog.LOG_ERR, str(e))
