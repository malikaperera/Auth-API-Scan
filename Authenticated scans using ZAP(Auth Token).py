#!/usr/bin/env python
import time
import requests
from pprint import pprint
from zapv2 import ZAPv2

#API key for ZAP
apiKey = '>Enter API key here<'

#Sets target to scan 
target = input("Enter target to be scanned:  ")

#Splitting URL to remove the path, so the entire domain could be included in the default context.
x = target.split('/')[2]
x2 = "https://"+x
t = x2+".*"

#Gets Authorization token from user
Auth = input("Enter Auth token for API: " )

#Displays the domain which would be included in the default context
print(t)

#Creating the ZAP instance
zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})

#Setting global variable
headers = {
  'Accept': 'application/json',
  'X-ZAP-API-Key': '>Enter API key here<'
}

r = requests.get('http://zap/JSON/script/action/setGlobalVar/', params={
  'varKey': "Auth",
  'varValue': Auth
}, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}, headers = headers)

print (r.text)


#Includes the scanned target into the default context(After the spider scan,before the active scan)
def context():
    headers = {
      'Accept': 'application/json',
      'X-ZAP-API-Key': '1eubsn9ama8l16qkoe3ll7k1kt'
    }
    
    r = requests.get('http://zap/JSON/context/action/includeInContext/', params={
      'contextName': 'Default Context',  'regex': t
      }, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}, timeout=5, headers = headers)
    
    
    print(r.text)


#Sending header request
def headerrequest():
     headers = dict({'Authorization':'Token ' + Auth});
     def sendingRequest(msg, initiator, helper): 
        for x in list(headers):
          msg.getRequestHeader().setHeader(x, headers[x]);


     def responseReceived(msg, initiator, helper): 
        pass;  
        
#Function for the spider scan  
def spiderscan():
    print('Spidering target {}'.format(target))
    # The scan returns a scan id to support concurrent scanning
    scanID = zap.spider.scan(target)
    while int(zap.spider.status(scanID)) < 100:
        # Poll the status until it completes
        print('Spider progress %: {}'.format(zap.spider.status(scanID)))
        time.sleep(1)
    
    print('Spider has completed!')
    # Prints the URLs the spider has crawled
    print('\n'.join(map(str, zap.spider.results(scanID))))
    # If required post process the spider results
    

#Function for the active scan process
def activescan():    
    # TODO : explore the app (Spider, etc) before using the Active Scan API, Refer the explore section
    print('Active Scanning target {}'.format(target))
    scanID = zap.ascan.scan(target)
    
    while int(zap.ascan.status(scanID)) < 100:
        # Loop until the scanner has finished
        print('Scan progress %: {}'.format(zap.ascan.status(scanID)))
        time.sleep(5)
    
    print('Active Scan completed')
    # Print vulnerabilities found by the scanning
    print('Hosts: {}'.format(', '.join(zap.core.hosts)))
    print('Alerts: ')
    pprint(zap.core.alerts(target))
    
    
#Function calls    
spiderscan()
context()
headerrequest()
activescan()


 