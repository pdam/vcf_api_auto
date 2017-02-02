import sys

import time

sys.path.append(".")
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import requests
import json
from pprint import pprint
from vcfccli import vcfccli
class vcfapi(object):
    def __init__(self, vcf_ip, uname="admin", passwd="test123"):
        self.vcf_ip = vcf_ip
        self.uname = uname
        self.passwd = passwd
        s = requests.session()
        self.s=s
        login_data = dict(j_username=uname, j_password=passwd)
        s.post('https://%s/vcf-center/auth/ss_login' % vcf_ip, data=login_data, verify=False)


    def getAPISession(self):
        return self.s

    def createSeedSwitch(self,seed_ip,seed_user,seed_pass):
        pprint("## Add a   seed   switch")
        seedswitchpayload = {"name": "local-%d" % int(time.time()), "mgmt-ip": seed_ip, "username": seed_user,
                             "password": seed_pass}
        r = self.s.post('https://%s/vcf-center/api/switch' % self.vcf_ip, json=seedswitchpayload, verify=False)
        print r.text
        assert r.status_code == 201
        json_switches = self.s.get("https://%s/vcf-center/api/switch" % self.vcf_ip, verify=False).json()
        switch_id,switch_name = [(x["id"],x["vrest-switch"]["name"]) for x in json_switches if x["vrest-switch"]["mgmt-ip"] == seed_ip][0]
        return switch_id,switch_name

    def  createPCAPAgent(self):
        cliobj = vcfccli(self.vcf_ip)
        ifacejson = [{"name": "null", "ip": cliobj.getInterfaceIP("eth1"), "iface": "eth1",
                      "mac": cliobj.getInterfaceMac("eth1"), "include": "true"},
                     {"name": "null", "ip": cliobj.getInterfaceIP("eth0"), "iface": "eth0",
                      "mac": cliobj.getInterfaceMac("eth0"), "include": "true"}]

        pprint("#create a pcap engine")
        pcap_name= "local-%d" % int(time.time())
        pcapenginedata = {"external": "false", "ifaces": ifacejson, "name": pcap_name ,
                          "ip": "%s" % self.vcf_ip,
                          "port": "8080"}
        r = self.s.post('https://%s/vcf-center/api/pcapengine' % self.vcf_ip, json=pcapenginedata, verify=False)
        print r.text
        assert r.status_code == 201
        json_pcapagents = self.s.get("https://%s/vcf-center/api/pcapengine" % self.vcf_ip, verify=False).json()
        pcap_id = [x["id"] for x in json_pcapagents if x["name"] == pcap_name][0]
        return pcap_id,pcap_name


