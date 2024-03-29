## The easiest way for pushing Nessus scan results into Splunk via Python

| Created      | Modified     |
| ------------ | -------------|
| Nov 20, 2020 | Nov 18, 2022 |

*If you manage **`Nessus`** Professional and **`Splunk`** at your company, you must read this guide to overcome some barriers encountered towards the vulnerability management process.*

![Vulnerability Process](/images/vulnerability-assessment.png)

### pre-requirements

1. API Access Token and Secret Key of Nessus Professional
2. Splunk HTTP Event Collector Token
3. Environment variables 

| Variable Name      | Description     |
| ------------------ | ----------------|
| HEC_TOKEN          | Splunk HTTP Event Collector Token for authentication|
| N_ACCESS_KEY       | Nessus Access Key|
| N_SECRET_KEY       | Nessus Secret Key|

4. Change the `servers.json` file with your Nessus and Splunk IP or hostname

### How to use it

1. `git clone https://github.com/wlucenasec/nessus_HEC.git`
2. `python3 nessus_HEC.py`

YouTube Video walking through the process: https://youtu.be/d99NNH14iR0

Step-by-step : https://medium.com/@wlucenasec/the-easiest-way-for-pushing-nessus-scan-results-into-splunk-via-python-51a0affa7b60
