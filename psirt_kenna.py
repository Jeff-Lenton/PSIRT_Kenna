import sys
import requests
import json
import logging
import time
import credentials

logging.captureWarnings(True)

psirt_endpoint = "https://apix.cisco.com/security/advisories/v2/all"
kenna_endpoint = "https://api.trial1.eu.kennasecurity.com/vulnerability_definitions/"
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
	print ('Getting PSIRT data')
	psirt_json = get_psirt()

	for i in psirt_json['advisories']:
		advisory_id = i['advisoryId']
		advisory_title = i['advisoryTitle']
		for n in i['cves']:
			if n != 'NA':
				search_endpoint = kenna_endpoint + n
				response = requests.request("GET", search_endpoint, headers=kenna_headers)
				vuln_search = response.json()
				kenna_score = vuln_search['vulnerability_definition']['risk_meter_score']
				
				print (advisory_id)
				print (advisory_title)
				print (n)
				print (kenna_score)
				print ()

				time.sleep(.3)
		
	# print(json.dumps(psirt_json, indent=4))


get_kenna_cves()



