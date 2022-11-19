import requests, json,os, time

serverproperties = json.loads(open('servers.json').read())
splunk_address = f'{serverproperties["Splunk"]["Address"]}'+":"+f'{serverproperties["Splunk"]["Port"]}'
nessusScan_URL = "https://"+f'{serverproperties["Nessus"]["Address"]}'+":"+f'{serverproperties["Nessus"]["Port"]}'+"/scans/"
nessusScan_Hosts = nessusScan_URL+"/hosts/"

HEC_TOKEN = os.getenv('HEC_TOKEN') 
nessus_Auth = { 'X-ApiKeys': "accessKey="+os.getenv('N_ACCESS_KEY')+"; secretKey="+os.getenv('N_SECRET_KEY')}

def main():
    try:
        check_scans = requests.request("GET",nessusScan_URL, headers=nessus_Auth,verify=False)
        for ScanID in json.loads(check_scans.text)['scans']:
            nessusScanHistory = requests.request("GET", nessusScan_URL + f'{ScanID["id"]}'+"?limit=2500&includeHostDetailsForHostDiscovery=true", headers=nessus_Auth,verify=False)
            scanner_start = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(json.loads(nessusScanHistory.text)['info']['scanner_start']))
            scanner_end = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(json.loads(nessusScanHistory.text)['info']['scanner_end']))
            scanner_status=json.loads(nessusScanHistory.text)['info']['status']
            getNessusScan(ScanID['id'],scanner_start,scanner_end,scanner_status)
    except Exception as NessusError:
        print(NessusError)

def getNessusScan(ScanID,scanner_start,scanner_end,scanner_status):
    response_Nessus = requests.request("GET", nessusScan_URL + f'{ScanID}', headers=nessus_Auth,verify=False)
    if response_Nessus.status_code == 200:
        try:
            for machine in json.loads(response_Nessus.text)['hosts']:
                hostname = {'hostname':str(machine['hostname'])}
                response_host = requests.request("GET", nessusScan_URL + f'{ScanID}' +f"/hosts/{machine['host_id']}", headers=nessus_Auth, verify=True)
                for vulnerability in json.loads(response_host.text)['vulnerabilities']:
                    response_plugin = requests.request("GET", nessusScan_URL + f'{ScanID}' +\
                        f"/hosts/{machine['host_id']}/plugins/{vulnerability['plugin_id']}",\
                        headers=nessus_Auth, verify=False)
                    vulnerability.update(json.loads(response_plugin.text))
                    vulnerability.update(hostname)
                    vulnerability.update({'scanner_start':str(scanner_start)})
                    vulnerability.update({'scanner_end':str(scanner_end)})
                    vulnerability.update({'scanner_status':str(scanner_status)})
                    sendSplunk(vulnerability)
        except:
            next
    else:
        print("The server seems not working.")

def sendSplunk(nessus_Scan):
    data = {}
    data.update({"index":"main"})
    data.update({"sourcetype":"_json"})
    data.update({"host":"nessus"})
    data.update({"event":nessus_Scan})  
    HEC_url = "https://"+splunk_address+"/services/collector/event"
    authheader = {'Authorization': 'Splunk '+f'{HEC_TOKEN}'}
    try:
        send = requests.request("POST",HEC_url,headers=authheader,json=data,verify=False)
        if send.status_code!=200:
            print("Vulnerability was not sent to Splunk.")
    except Exception as SplunkError:
        print(SplunkError)

if __name__ == "__main__":
    main()