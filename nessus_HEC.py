import requests, json

HEC_token = "4f8a3c6c-bbb8-4d0b-9a3b-4d9168abafe3" #YOUR HEC TOKEN
splunk_address = "localhost" #YOUR SPLUNK IP OR HOSTNAME

nessusScan_URL = "https://192.168.15.20:8834/scans/13/" #YOUR NESSUS SCAN URL
nessusScan_Hosts = nessusScan_URL+"/hosts/"       
nessus_Auth = {'X-ApiKeys': "accessKey={YOUR ACCESS KEY}; secretKey={YOUR SECRET KEY}"}

def main():
    getNessusScan()
    
def getNessusScan():
    response_Nessus = requests.request("GET", nessusScan_URL, headers=nessus_Auth, verify=False)
    if response_Nessus.status_code == 200:
        parseJSON = json.loads(response_Nessus.text)
        for machine in parseJSON['hosts']:
            url_hostid = nessusScan_Hosts + str(machine['host_id'])
            hostname = {'hostname':str(machine['hostname'])}
            response_host = requests.request("GET", url_hostid, headers=nessus_Auth, verify=False)
            parseJSON_Host = json.loads(response_host.text)
            for vulnerability in parseJSON_Host['vulnerabilities']:
                vulnerability.update(hostname)
                sendSplunk(vulnerability)
    else:
        print("The server seems not working.")

def sendSplunk(nessus_Scan):
    data = {}
    data.update({"index":"idx_nessus"})
    data.update({"sourcetype":"nessuspro"})
    data.update({"source":"index_nessus"})
    data.update({"host":"nessus"})
    data.update({"event":nessus_Scan})  
    HEC_url = "https://"+splunk_address+":8088/services/collector/event"
    authheader = {'Authorization': 'Splunk '+HEC_token}
    send = requests.request("POST",HEC_url,headers=authheader,json=data,verify=False)

if __name__ == "__main__":
    main()
