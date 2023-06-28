import sys
import requests
import json
import logging
import time
import credentials
import csv

logging.captureWarnings(True)

psirt_endpoint = "https://apix.cisco.com/security/advisories/v2/all"
kenna_endpoint = "https://api.eu.kennasecurity.com/vulnerability_definitions/"
kenna_headers = {'content-type': 'application/json', 'X-Risk-Token':credentials.kenna_api_token}

def get_new_token():

	auth_server_url = "https://id.cisco.com/oauth2/default/v1/token"
	token_req_payload = {'grant_type': 'client_credentials'}

	token_response = requests.post(auth_server_url,
	data=token_req_payload, verify=False, allow_redirects=False,
	auth=(credentials.client_id, credentials.client_secret))
				 
	if token_response.status_code !=200:
		print("Failed to obtain token from the OAuth 2.0 server", file=sys.stderr)
		sys.exit(1)
	else:
		print("Successfuly obtained a new token")
		print ("Getting PSIRT data - please wait")
		tokens = json.loads(token_response.text)
	return tokens['access_token']


def get_psirt():
	
	token = get_new_token()
	api_call_headers = {'Authorization': 'Bearer ' + token}
	api_call_response = requests.get(psirt_endpoint, headers=api_call_headers, verify=False)

	if	api_call_response.status_code == 401:
		token = get_new_token()
	else:
		psirt_data = json.loads(api_call_response.text)
		return psirt_data


def get_kenna_cves():

	psirt_json = get_psirt()
	print ("Getting Kenna Scores...")
	header = ['Advisory Title', 'Advisory ID', 'CVE', 'Kenna Score', 'Active Breach', 'Malware Exploitable', 'Easily Exploitable', 'Popular Target', 'Remote Code Execution', 'Pre-NVD Chatter']
	output = open('psirt_kenna_scores.csv', 'w')
	writer = csv.writer(output)
	writer.writerow(header)

	for i in psirt_json['advisories']:
		advisory_id = i['advisoryId']
		advisory_title = i['advisoryTitle']
		for n in i['cves']:
			if n != 'NA':
				search_endpoint = kenna_endpoint + n
				response = requests.request("GET", search_endpoint, headers=kenna_headers)
				vuln_search = response.json()
				kenna_score = vuln_search['vulnerability_definition']['risk_meter_score']
				active_internet_breach = vuln_search['vulnerability_definition']['active_internet_breach']
				malware_exploitable = vuln_search['vulnerability_definition']['malware_exploitable']
				easily_exploitable = vuln_search['vulnerability_definition']['easily_exploitable']
				popular_target = vuln_search['vulnerability_definition']['popular_target']
				remote_code_execution = vuln_search['vulnerability_definition']['remote_code_execution']
				pre_nvd_chatter = vuln_search['vulnerability_definition']['pre_nvd_chatter']
				row = advisory_title,advisory_id,n,kenna_score,active_internet_breach,malware_exploitable,easily_exploitable,popular_target,remote_code_execution,pre_nvd_chatter
				writer.writerow(row)
				time.sleep(.3)
	output.close()
	print ("Done - check output CSV")

if __name__ == "__main__":
	get_kenna_cves()



