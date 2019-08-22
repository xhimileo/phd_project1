#hping3-1 --flood -a 192.168.33.123192.168.1.255

import os
import sys
import re
import uuid
import socket
import struct
import binascii
import pandas as pd
df=pd.DataFrame()

mac_dict = {}
ip_mac_dict = {}
ping_dict = {}

count = 0
pcount = 0
p2count = 0

recent_activities = []

my_ip = os.popen('hostname -I').read().split(" ")[0]
my_mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1])

def detect_attacker(mac_dict):
	try:
		t = max(mac_dict.values())
	except ValueError:
		return None

	for i in mac_dict.keys():
		if mac_dict[i] == t:
			return i

def clear():
	os.system('clear')

def display(recent_activities):
	clear()
	if count<5:
		flag = False
	else:
		flag = True
	if pcount<5:
		flag2 = False
	else:
		flag2 = True
	if p2count<20:
		flag3 = False
	else:
		flag3 = True

	msg = ""
	attacker_mac = None
	attacker_ip = None
	pingattacker_mac = None
	pingattacker_ip = None

	if flag3 or flag2:	
		pingattacker_mac = detect_attacker(ping_dict)
		if pingattacker_mac in ip_mac_dict:
			pingattacker_ip = ip_mac_dict[pingattacker_mac]

	if flag:	
		attacker_mac = detect_attacker(mac_dict)
		if attacker_mac in ip_mac_dict:
			attacker_ip = ip_mac_dict[attacker_mac]
	for activity in recent_activities[::-1]:
		for i in activity:
			msg+=i+"\n"
		msg+="=================\n"

	label = '''
[+] Total Ping Requests: {}
[+] Ping of Death: {}

\t[+] Potential Source:
\t\tIP: {}
\t\tMAC ADDRESS: {}

[+] ICMP Smurf Attack: {}

[+] Recent Activities:

{}

[+] Potential Attacker Details: 

\tIP: {}
\tMAC ADDRESS: {}
'''.format(p2count,flag2,pingattacker_ip,pingattacker_mac,flag,msg,attacker_ip,attacker_mac)

	print(label)

s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))

while True:
	try:
		temp = []
		display(recent_activities)
		if len(recent_activities)>5:
			recent_activities = recent_activities[-5:]
		pkt=s.recvfrom(65565)
		ethhead=pkt[0][0:14]
		eth=struct.unpack("!6s6s2s",ethhead)
		dest_mac = ':'.join(re.findall('..', binascii.hexlify(eth[0]).decode("utf-8")))
		src_mac = ':'.join(re.findall('..', binascii.hexlify(eth[1]).decode("utf-8")))
		temp.append("#ETH# SRC MAC = {} --> DEST MAC = {}".format(src_mac,dest_mac))

		if eth[2]==b'\x08\x06':
			arp_hdr = pkt[0][14:42]
			arp= struct.unpack("2s2s1s1s2s6s4s6s4s", arp_hdr)
			src_mac = ':'.join(re.findall('..',binascii.hexlify(arp[5]).decode("utf-8")))
			dest_mac = ':'.join(re.findall('..',binascii.hexlify(arp[7]).decode("utf-8")))
			src_ip = socket.inet_ntoa(arp[6])
			dest_ip = socket.inet_ntoa(arp[8])
			if src_mac not in ip_mac_dict:ip_mac_dict[src_mac]=src_ip
			if dest_mac not in ip_mac_dict:ip_mac_dict[dest_mac]=dest_ip

		else:
			try:
				ipheader=pkt[0][14:34]
				ip_hdr=struct.unpack('!BBHHHBBH4s4s',ipheader)
				src_ip = str(socket.inet_ntoa(ip_hdr[8]))
				dest_ip = str(socket.inet_ntoa(ip_hdr[9]))
				
				if ip_hdr[6]==1:
					temp.append("#ICMP# SRC IP = {} --> DEST IP = {}".format(src_ip,dest_ip))
					if src_ip == my_ip and src_mac != my_mac:
						count+=1
						if src_mac not in mac_dict:mac_dict[src_mac]=0
						else:mac_dict[src_mac]+=1
					if dest_mac == my_mac:
						if len(pkt[0][38:])>1004:
							pcount+=1
						p2count+=1
						if src_mac not in ping_dict:ping_dict[src_mac]=0
						else:ping_dict[src_mac]+=1

			except(struct.error,TypeError):
				pass
		recent_activities.append(temp)

	except KeyboardInterrupt:
		print("\n[+] Program Stopped...")
		sys.exit()