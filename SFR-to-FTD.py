########################################################################
#################### Stage 1 ### connect to server######################
########################################################################

import json
import sys
import requests
import math

with open('old-zones.json') as data_file:
    oldzones = json.load(data_file)
with open('new-zones.json') as data_file:
    newzones = json.load(data_file)
########################################################################
ip = input("FMC IP address: ")
server = "https://" + ip
username = input("username: ")
if len(sys.argv) > 1:
    username = sys.argv[1]
password = input("password: ")
if len(sys.argv) > 2:
    password = sys.argv[2]
# cert_path = input("Enter FMC Certificate Path or type (False) if you don't have it: ")
r = None
headers = {'Content-Type': 'application/json'}

api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
auth_url = server + api_auth_path
try:
    # REST call with SSL verification turned off:
    r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username, password), verify=False)
    # REST call with SSL verification turned on: Download SSL certificates from your FMC first and provide its path for verification.
    # r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
    auth_headers = r.headers
    auth_token = auth_headers.get('X-auth-access-token', default=None)
    refresh_token = auth_headers.get('X-auth-refresh-token', default=None)
    Domain_id = auth_headers.get('DOMAIN_UUID', default=None)
    if auth_token == None:
        print("auth_token not found. Exiting...")
        sys.exit()
except Exception as err:
    print("Error in generating auth token --> " + str(err))
    sys.exit()
###################################################################
################## Stage #2 ### Read all AP #######################
###################################################################
api_path = "/api/fmc_config/v1/domain/" + Domain_id + "/policy/accesspolicies"
url = server + api_path
if (url[-1] == '/'):
    url = url[:-1]
headers['X-auth-access-token'] = auth_token
headers['X-auth-refresh-token'] = refresh_token
# GET OPERATION
try:
    # REST call with SSL verification turned off:
    r = requests.get(url, headers=headers, verify=False)
    status_code = r.status_code
    resp = r.text
    if (status_code == 200):
        print("GET successful. Response data --> ")
        json_resp = json.loads(resp)
    else:
        r.raise_for_status()
        print("Error occurred in GET --> " + resp)
except requests.exceptions.HTTPError as err:
    print("Error in connection --> " + str(err))
finally:
    if r: r.close()
policies = json_resp['items']
policy_n = len(policies);
for xxx in range(0, policy_n):
    print(xxx + 1, policies[xxx]['name'], policies[xxx]['id'])
Source_policy = int(input("enter the source policy number : "))
xxx = Source_policy - 1
Source_policy_id = policies[xxx]['id']
Destination_policy = int(input("enter the destinitation policy number : "))
xxx = Destination_policy - 1
Destination_policy_id = policies[xxx]['id']
###################################################################
####### Stage #3 ### Read number of rules in Src policy############
###################################################################
limit = 1
headers['X-auth-access-token'] = auth_token
headers['X-auth-refresh-token'] = refresh_token
api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/" + Source_policy_id + "/accessrules?limit=" + str(
    limit)
# param
url = server + api_path
if (url[-1] == '/'):
    url = url[:-1]
# GET OPERATION
try:
    # REST call with SSL verification turned off:
    r = requests.get(url, headers=headers, verify=False)
    # REST call with SSL verification turned on:
    # r = requests.get(url, headers=headers, verify=cert_path)
    status_code = r.status_code
    resp = r.text
    if (status_code == 200):
        print("GET successful. Response data --> ")
        json_resp = json.loads(resp)
    else:
        r.raise_for_status()
        print("Error occurred in GET --> " + resp)
except requests.exceptions.HTTPError as err:
    print("Error in connection --> " + str(err))
finally:
    if r: r.close()
lenold = len(oldzones)
lenNew = len(newzones)
###################### migration info #############################
input("press any key to view the migration info")
for iold in range(0, lenold):
    print("The old zone ", oldzones[iold]['name'], "will be ", newzones[iold]['name'])
print("the Source Policy contains", json_resp['paging']['count'], "rule")
###################################################################
############### Stage #4 ### Read Source Policy####################
###################################################################
start_rule = int(input("start editing from rule index number : "))
end_rule = int(input("to rule index number : "))
N_rules = end_rule - start_rule + 1
N_loop = math.ceil(N_rules / 500)
exp = "true"
limit = 500
print('Migration process will take ', N_loop, ' rounds')
########################
for m in range(1, N_loop + 1):
    print('round ', m)
    offset = (start_rule - 1) + (m - 1) * 500
    headers['X-auth-access-token'] = auth_token
    headers['X-auth-refresh-token'] = refresh_token
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/" + Source_policy_id + "/accessrules?expanded=" + exp + "&limit=" + str(
        limit) + "&offset=" + str(offset)
    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    # GET OPERATION
    try:
        # REST call with SSL verification turned off:
        r = requests.get(url, headers=headers, verify=False)
        # REST call with SSL verification turned on:
        # r = requests.get(url, headers=headers, verify=cert_path)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            print("GET successful. Response data --> ")
            json_resp = json.loads(resp)
        else:
            r.raise_for_status()
            print("Error occurred in GET --> " + resp)
    except requests.exceptions.HTTPError as err:
        print("Error in connection --> " + str(err))
    finally:
        if r: r.close()
    data = json_resp['items']
    #################################################
    ##################save original rules############
    #################################################
    dataoutputtest_data = data
    dataoutputtest = "OriginalRules" + str(m) + ".json"
    with open(dataoutputtest, 'w') as datatest_file:
        newdata = json.dump(dataoutputtest_data, datatest_file, indent=4)
        datatest_file.write("\n")
    ####################################################################################
    ########################### Stage5 # ### Edit Rules##################################
    ####################################################################################
    dataoutput = "NewRules" + str(m) + ".json"
    n = len(data);
    y = 0;

    if lenold == lenNew:
        for i in range(0, n):
            if data[i]['metadata']:
                del data[i]['metadata']
                del data[i]['links']
            if 'users' in data[i] and data[i]['users']['objects']:
                userel = data[i]['users']['objects']
                usersnobj = len(userel);
                for k in range(0, usersnobj):
                    if data[i]['users']['objects'][k]['type'] != "Realm":
                        del data[i]['users']['objects'][k]['realm']
            if 'sourceZones' in data[i]:
                if data[i]['sourceZones']['objects']:
                    el = data[i]['sourceZones']['objects']
                    nobj = len(el);
                    for j in range(0, nobj):
                        for ii in range(0, lenNew):
                            if el[j]['name'] == oldzones[ii]['name']:
                                el[j]['name'] = newzones[ii]['name']
                                el[j]['id'] = newzones[ii]['id']
                                x = True
                                break
                            else:
                                x = False
                                y = el[j]['name']
                        if x == False:
                            print(y)
            if 'destinationZones' in data[i]:
                if data[i]['destinationZones']['objects']:
                    el = data[i]['destinationZones']['objects']
                    nobj = len(el);
                    for j in range(0, nobj):
                        for ii in range(0, lenNew):
                            if el[j]['name'] == oldzones[ii]['name']:
                                el[j]['name'] = newzones[ii]['name']
                                el[j]['id'] = newzones[ii]['id']
                                x = True
                                break
                            else:
                                x = False
                                y = el[j]['name']
                        if x == False:
                            print(y)
        ####################################################################################
        ########################### save new rules##########################################
        ####################################################################################
        with open(dataoutput, 'w') as data_file:
            newdata = json.dump(data, data_file, indent=4)
            data_file.write("\n")
        print("Round ", str(m), " of editing done")
    else:
        print("New zones Don't equal old zones")
    post_data = data
    ########################################################################
    ###########################Stage #6### post process#####################
    ########################################################################
    headers['X-auth-access-token'] = auth_token
    headers['X-auth-refresh-token'] = refresh_token

    api_path = "/api/fmc_config/v1/domain/" + Domain_id + "/policy/accesspolicies/" + Destination_policy_id + "/accessrules?bulk=true"
    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]

    # POST OPERATION
    try:
        # REST call with SSL verification turned off:
        r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
        # REST call with SSL verification turned on:
        # r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')
        status_code = r.status_code
        resp = r.text
        print("Status code is: " + str(status_code))
        if status_code == 201 or status_code == 202:
            print("Post was successful...")
            json_resp = json.loads(resp)
            # print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
        else:
            r.raise_for_status()
            print("Error occurred in POST --> " + resp)
    except requests.exceptions.HTTPError as err:
        print("Error in connection --> " + str(err))
    finally:
        if r: r.close()
    print("Round ", m, " Posting process Completed Successflly")
###############################################################
print("Rules Migration Completed Successfully")

###################################################################
############### Stage #4 ### Read Source Policy####################
###################################################################
print("integrity check... please wait!")
########################
for m in range(1, N_loop + 1):
    print('round ', m)
    offset = (start_rule - 1) + (m - 1) * 500
    headers['X-auth-access-token'] = auth_token
    headers['X-auth-refresh-token'] = refresh_token
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/" + Source_policy_id + "/accessrules?expanded=" + exp + "&limit=" + str(
        limit) + "&offset=" + str(offset)
    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    # GET OPERATION
    try:
        # REST call with SSL verification turned off:
        r = requests.get(url, headers=headers, verify=False)
        # REST call with SSL verification turned on:
        # r = requests.get(url, headers=headers, verify=cert_path)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            print("GET successful. Response data --> ")
            json_resp = json.loads(resp)
        else:
            r.raise_for_status()
            print("Error occurred in GET --> " + resp)
    except requests.exceptions.HTTPError as err:
        print("Error in connection --> " + str(err))
    finally:
        if r: r.close()
    data1 = json_resp['items']
    ###########################################
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/" + Destination_policy_id + "/accessrules?expanded=" + exp + "&limit=" + str(
        limit) + "&offset=" + str(offset)
    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    # GET OPERATION
    try:
        # REST call with SSL verification turned off:
        r = requests.get(url, headers=headers, verify=False)
        # REST call with SSL verification turned on:
        # r = requests.get(url, headers=headers, verify=cert_path)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            print("GET successful. Response data --> ")
            json_resp = json.loads(resp)
        else:
            r.raise_for_status()
            print("Error occurred in GET --> " + resp)
    except requests.exceptions.HTTPError as err:
        print("Error in connection --> " + str(err))
    finally:
        if r: r.close()
    data2 = json_resp['items']

    nnn = len(data1)
    for i in range(0, nnn-1):
        if data1[i] != data2[i]:
            #print("Rule ", [i], " mismatch")
            print(data1[0]['name'], "equal", data2[0]['name'])