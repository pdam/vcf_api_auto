from pprint import pprint
import paramiko
import thread

import time


class vcfccli(object):
    def __init__(self, vcfc_ip, uname="vcf", passwd="changeme"):
        self.vcfc_ip = vcfc_ip
        self.uname = uname
        self.passwd = passwd

        self.sshclient = paramiko.SSHClient()
        self.sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.sshclient.connect(vcfc_ip, username=self.uname, password=self.passwd)
        stdin, stdout, stderr = self.sshclient.exec_command("uptime\n")
        pprint(stdout.readlines())



    def removeConfigs(self):
        stdin, stdout, stderr = self.sshclient.exec_command("rm  /home/vcf/srv/vcf/config/flowfilters.json")
        stdin, stdout, stderr = self.sshclient.exec_command("rm  /home/vcf/srv/vcf/config/pcap-agent.properties")
        stdin, stdout, stderr = self.sshclient.exec_command("rm  /home/vcf/srv/vcf/config/pcap-engine.json")
        stdin, stdout, stderr = self.sshclient.exec_command("rm  /home/vcf/srv/vcf/config/vcf-center.properties")
        stdin, stdout, stderr = self.sshclient.exec_command("rm  /home/vcf/srv/vcf/config/pcap_agents.properties")
        stdin, stdout, stderr = self.sshclient.exec_command("rm  /home/vcf/srv/vcf/config/pcap-file.json")
        stdin, stdout, stderr = self.sshclient.exec_command("rm  /home/vcf/srv/vcf/config/switch-details.json")
        stdin, stdout, stderr = self.sshclient.exec_command("rm  /home/vcf/srv/vcf/config/vcf-license.json")
        stdin, stdout, stderr = self.sshclient.exec_command("rm  /home/vcf/srv/vcf/config/vcf-maestro.properties")
        self.stopVCFC()
        time.sleep(10)
        self.startVCFC()
        time.sleep(10)

    def getInterfaceMac(self , interface):
        stdin, stdout, stderr = self.sshclient.exec_command("ifconfig %s | grep HWaddr | awk '{print $5}'"%interface)
        return stdout.readline().strip()

    def getInterfaceIP(self , interface):
        stdin, stdout, stderr = self.sshclient.exec_command("ifconfig %s | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'"%interface)
        return stdout.readline().strip()

    def startVCFC(self):
        stdin, stdout, stderr = self.sshclient.exec_command("/srv/vcf/bin/start-vcfc.sh")
        pprint(stdout.readlines())


    def stopVCFC(self):
        stdin, stdout, stderr = self.sshclient.exec_command("/srv/vcf/bin/stop-vcfc.sh")
        pprint(stdout.readlines())