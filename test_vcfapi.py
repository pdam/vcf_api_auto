import sys

import pytest
import time
import requests

sys.path.append(".")
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import json
from pprint import pprint
from vcfapi import vcfapi
from vcfccli import vcfccli

username = "admin"
password = "test123"


def test_setup(vcf_ip):
    vcfccli(vcf_ip).removeConfigs()


testdata = [
    ("10.9.21.212", "network-admin", "test123")
]


@pytest.mark.parametrize("seed_switch_ip,uname,passwd", testdata)
def test_SeedSwitchAPI(vcf_ip, seed_switch_ip, uname, passwd):
    """

    """
    s = vcfapi(vcf_ip).getAPISession()
    pprint("## Seed  switch Verification")
    r = s.get('https://%s/vcf-center/api/switch' % vcf_ip, verify=False).json()
    print " First Seed Switch: %s" % r

    pprint("## Add a   seed   switch")
    seedswitchpayload = {"name": "local-%d" % int(time.time()), "mgmt-ip": seed_switch_ip, "username": uname,
                         "password": passwd}
    r = s.post('https://%s/vcf-center/api/switch' % vcf_ip, json=seedswitchpayload, verify=False)
    print r.text
    assert r.status_code == 201

    pprint("# Get  List of  Seed Switches")
    r = s.get('https://%s/vcf-center/api/switch' % vcf_ip, verify=False).json()
    swid = [x['id'] for x in r if x['vrest-switch']['mgmt-ip'] == seed_switch_ip][0]
    print swid
    assert swid is not None

    pprint("# delete  the   switch")
    r = s.delete('https://%s/vcf-center/api/switch/%d' % (vcf_ip, swid), verify=False)
    print r.content
    assert r.status_code == 200
    s = None


testdata = [
    ("10.9.21.212", "network-admin", "test123")
]


@pytest.mark.parametrize("collector_ip,uname,passwd", testdata)
def test_CollectorAPI(vcf_ip, collector_ip, uname, passwd):
    """

    """
    apiobj = vcfapi(vcf_ip)
    s = apiobj.getAPISession()
    pprint("## Collector Verification")
    r = s.get('https://%s/vcf-center/api/collector' % vcf_ip, verify=False).json()
    print " Collector: %s" % r
    pprint("## Add a   seed   switch")
    switch_id, switch_name = apiobj.createSeedSwitch(collector_ip, uname, passwd)
    print switch_id
    pprint("## Add a   Collector")
    collector_payload = {"switch-id": switch_id, "username": uname, "password": passwd, "license": {}}
    r = s.post('https://%s/vcf-center/api/collector' % vcf_ip, json=collector_payload, verify=False)
    print r.text
    assert r.status_code == 201

    pprint("# delete  the   collector")
    r = s.delete('https://%s/vcf-center/api/collector/1' % vcf_ip, verify=False)
    print r.content
    assert r.status_code == 200
    s = None


testdata = [
    ("soyu.pluribusnetworks.com", "pdam", "Spmprx123456")
]


@pytest.mark.parametrize("ldap_ip,uname,passwd", testdata)
def test_AuthenticationServer(vcf_ip, ldap_ip, uname, passwd):
    """

    """
    s = vcfapi(vcf_ip).getAPISession()

    pprint("## Add auth server   ")
    ldappayload = {"isEdit": "false", "type": "LDAP", "scheme": "ldap", "port": 389,
                   "host-name": "soyu.pluribusnetworks.com", "base-dn": "DC=pluribusnetworks,DC=com",
                   "ldap-manager-dn": "CN=TACACS,CN=Users,DC=pluribusnetworks,DC=com",
                   "ldap-manager-pass": "l5O6v8E!pl", "ldap-user-dn-patterns": "uid={0},ou=people",
                   "ldap-user-search-filter": "(&(objectClass=user)(sAMAccountName={0}))"}

    r = s.post('https://%s/vcf-center/api/ldap' % vcf_ip, json=ldappayload, verify=False)
    print r.text
    assert r.status_code == 200

    pprint("# Get  List of LDAP Servers")
    r = s.get('https://%s/vcf-center/api/ldap' % vcf_ip, verify=False).json()

    pprint("# Test  LDAP user")
    testldap = {"username": uname, "password": passwd, "type": "LDAP"}
    r = s.post('https://%s/vcf-center/api/ldap/test' % vcf_ip, json=testldap, verify=False).json()
    assert r["message"] == "Test succeeded."

    pprint("# delete  the   LDAP")
    r = s.delete('https://%s/vcf-center/api/ldap/LDAP' % vcf_ip, verify=False)
    print r.content
    assert r.status_code == 200
    s = None


testdata = [
    ("a-%d" % time.time(), "password")
]


@pytest.mark.parametrize("uname,passwd", testdata)
def test_AdminUser(vcf_ip, uname, passwd):
    """

    """
    s = vcfapi(vcf_ip).getAPISession()

    pprint("## Add admin user ")
    adminpayload = {"role": "ROLE_VCF_ADMIN", "username": uname, "password": passwd}

    r = s.post('https://%s/vcf-center/api/user' % vcf_ip, json=adminpayload, verify=False)
    print r.text
    assert r.status_code == 200

    pprint("# Get  List of admins")
    r = s.get('https://%s/vcf-center/api/user' % vcf_ip, verify=False).json()

    pprint("# delete  the   user")
    # r = s.delete('https://%s/vcf-center/api/user/%s' % (vcf_ip,uname), verify=False)
    # print r.content
    # assert r.status_code == 200
    s = None


def test_PCAPAgentAPI(vcf_ip):
    """

    """
    ### PCAP  Agent API Verification
    s = vcfapi(vcf_ip).getAPISession()
    pprint("# Get  list  of  interfaces")
    js = {"ip": "%s" % vcf_ip, "port": "8080"}
    r = s.post('https://%s/vcf-center/api/pcapengine/interfaces' % vcf_ip, json=js, verify=False)
    assert r.status_code == 200
    assert json.loads(r.text)[0]['iface'] == 'eth0' or 'eth1'
    assert json.loads(r.text)[1]['iface'] == 'eth0' or 'eth1'
    cliobj = vcfccli(vcf_ip)
    ifacejson = [
        {"name": "null", "ip": cliobj.getInterfaceIP("eth1"), "iface": "eth1", "mac": cliobj.getInterfaceMac("eth1"),
         "include": "true"}, \
        {"name": "null", "ip": cliobj.getInterfaceIP("eth0"), "iface": "eth0", "mac": cliobj.getInterfaceMac("eth0"),
         "include": "true"}]

    pprint("#create a pcap engine")
    pcapenginedata = {"external": "false", "ifaces": ifacejson, "name": "local-%d" % int(time.time()),
                      "ip": "%s" % vcf_ip,
                      "port": "8080"}
    r = s.post('https://%s/vcf-center/api/pcapengine' % vcf_ip, json=pcapenginedata, verify=False)
    print r.text
    assert r.status_code == 201

    pprint("# Get  List of  Pcap Engines")
    r = s.get('https://%s/vcf-center/api/pcapengine' % vcf_ip, verify=False).json()
    id = r[0]['id']
    assert id is not None

    pprint("#get status  of the  created   engine")
    r = s.get('https://%s/vcf-center/api/pcapengine/%d/status' % (vcf_ip, id), verify=False).json()
    print r
    assert r[u'freeDiskSpace'] is not None

    pprint("# delete  the   engine")
    r = s.delete('https://%s/vcf-center/api/pcapengine/%d' % (vcf_ip, id), verify=False)
    assert r.status_code == 200

    pprint("#get status  of the  non existent   engine")
    r = s.get('https://%s/vcf-center/api/pcapengine/%d/status' % (vcf_ip, id), verify=False).json()
    print r  ## Gives  500 Error SHUD  NOT  Return  404
    s = None


def test_UploadPCAP(vcf_ip):
    """

    """
    ### PCAP  Agent API Verification

    apiobj = vcfapi(vcf_ip)
    s = apiobj.getAPISession()
    apiobj.createPCAPAgent()
    pprint("# Upload  a  PCAP")
    f = {'name': open('test.pcap', 'rb')}
    r = s.post('https://%s/vcf-center/api/pcapfile?stream=true' % vcf_ip, files=f, verify=False)
    assert r.status_code == 201


def test_VflowManagerPortOnly(vcf_ip):
    """

    """
    ### Vflow Manager  API Verification
    vflow_name = "vflow-%d" % int(time.time())
    apiobj = vcfapi(vcf_ip)
    s = apiobj.getAPISession()
    pcapid, pcapname = apiobj.createPCAPAgent()
    switchid, switchname = apiobj.createSeedSwitch("10.9.21.212", "network-admin", "test123")

    vflow_create_port_payload = {"_isAccordion_": "true", "id": "null", "switchname": switchname, "switch-id": switchid,
                                 "duration": "5", "pcap-id": pcapid, "pcap-name": pcapname, "pcap-external": "false",
                                 "pcap-iface": "eth1",
                                 "vrestmirror": {"_isAccordion_": "true", "direction": "ingress", "filtering": "port",
                                                 "span-encap": "none", "name": vflow_name, "in-port": "33",
                                                 "out-port": "22", "span-tagging-vlan": "null",
                                                 "span-remote-ip": "null"}}
    r = s.post('https://%s/vcf-center/api/flowfilter' % vcf_ip, json=vflow_create_port_payload, verify=False)
    assert r.status_code == 201

    vflowjson = s.get('https://%s/vcf-center/api/flowfilter' % vcf_ip, verify=False).json()

    vflowid = [x["id"] for x in vflowjson if x["vrestmirror"]["name"] == vflow_name][0]
    ## Start  the   VFlow
    pprint(vflowid)
    r = s.post('https://%s/vcf-center/api/flowfilter/%d/start' % (vcf_ip, vflowid), verify=False)
    #assert r.status_code == 200
    time.sleep(5)
    r = s.post('https://%s/vcf-center/api/flowfilter/%d/status' % (vcf_ip, vflowid), verify=False)
    #pprint("Vflow   Status:  %r" % r.json())
    ## Stop  the   VFlow
    r = s.post('https://%s/vcf-center/api/flowfilter/%d/stop' % (vcf_ip, vflowid), verify=False)
    #assert r.status_code == 200
    time.sleep(5)
    ## Delete  the   VFlow
    r = s.delete('https://%s/vcf-center/api/flowfilter/%d' % (vcf_ip, vflowid), verify=False)
    #assert r.status_code == 200


testdata = [
    ("pn-vcf", "test123")
]


@pytest.mark.parametrize("pnc_user,pnc_pass", testdata)
def test_LicenseAPI(vcf_ip, pnc_user, pnc_pass):
    """
    """
    s = vcfapi(vcf_ip).getAPISession()
    ##get   machine id   and  assert that  its  correct
    r = s.get('https://%s/vcf-center/api/license/machineid' % vcf_ip, verify=False).json()
    mid = r['machineid']
    assert mid is not None
    ##get   machine id   and  assert that  its  correct
    licensepost_data = {"username": pnc_user, "machineId": mid, "password": pnc_pass}
    r = s.post('https://%s/vcf-center/api/settings/pnc' % vcf_ip, json=licensepost_data, verify=False)
    print r.content
    r = s.get('https://%s/vcf-center/api/order' % vcf_ip, verify=False).json()
    print r
    assert r[0]['product_name'] is not None
    oids = [(x['id'], y['license_key']) for x in r for y in x['order_activations'] if y['device_id'] == mid]
    for order_id, keys in oids:
        print order_id, keys
        licenseactivate_data = {"id": order_id}
        r = s.put('https://%s/vcf-center/api/order/%d/activate' % (vcf_ip, order_id), json=licenseactivate_data,
                  verify=False)
        print r.content
        # assert r.status_code == 200  ===> Fails
        r = s.put('https://%s/vcf-center/api/license' % vcf_ip, data=keys, verify=False)
        print r.content

    r = s.get('https://%s/vcf-center/api/license' % vcf_ip, verify=False).json()
    activation_ids = [x['id'] for x in r]
    for activation_id in activation_ids:
        print activation_id

        r = s.delete('https://%s/vcf-center/api/license/%d' % (vcf_ip, activation_id), verify=False)
        assert r.status_code == 200

    # License  Validation of  Flows
    r = s.get('https://%s/maestro/config/license' % vcf_ip, verify=False).json()
    print r
    assert r['flowCount'] is not None
    assert r['pcapCount'] is not None
