#!/usr/local/bin/python2.7

import sys
import getopt
import datetime
import string
import shutil
from scapy.all import *

VERS = '0.1'
AUTHOR = 'Author: @BerghemHackLab'
NAME = 'arpscanspoof'
INFO = NAME + ' rel. ' + VERS + ' Open Source Project\n' + AUTHOR
badflags = [0,41,55,64]
foundbadflag = []
DNSquery = []
file_parameter = False
rebuild_pcap = False

portlist = {}
flagstcp = {}
IPSourceFlow = {}
HTTP_Response=[]
URL_Request=[]
UserAgent=[]
Attachment=[]
SQL_Injection=[]
XSS=[]
dnscounter=0
IPlist=[]
path_output=""
		
def parsepcap(pcap, target, geo, rebuild_pcap):
	counter=0
	ipcounter=0
	tcpcounter=0
	udpcounter=0
	arpcounter=0
	httpcounter= 0	
	pkts = rdpcap(pcap)
						
	for pkt in pkts:
		#a= 1
		counter += 1
		if TCP in pkt:						
			if target == "":
				tcpcounter += 1		
				TCP_parse(pkt, counter)					
			else:
				#Only if src or dst IP is my filter
				if pkt[IP].dst == target or pkt[IP].src == target:
					tcpcounter += 1
					TCP_parse(pkt,counter)
			
		elif UDP in pkt:  
			if target == "":
				udpcounter += 1
				UDP_parse(pkt)
			else:
				if IP in pkt:  
					if pkt[IP].dst == target or pkt[IP].src == target:
						UDP_parse(pkt)
				
		elif ARP in pkt:
			arpcounter += 1
		if IP in pkt:  
			if target == "":
				ipcounter += 1
				IP_parse(pkt) 
			else:
				if pkt[IP].dst == target or pkt[IP].src == target:
					ipcounter += 1 
					IP_parse(pkt)

	DisplayStat(counter,target,ipcounter,tcpcounter, udpcounter, arpcounter)
		
	if rebuild_pcap != "":
		rebuild(pcap, rebuild_pcap)

	if geo == True:	
		googlegeoip()				

def get_usage():	
	print INFO
	print '\nUsage: python pcaparse.py -f nomefile.pcap -r -o folder\n'
	print '  -h, --help'
	print '    print these help informations\n'
	print '  -f, --file'
	print '    file pcap to analyze\n'
	print '  -v, --version'
	print '    print the software release\n'
	print '  -o, --output \n'
	print '    output folder for rebuild files \n'
	print '  -g, --geo \n'
	print '    use geo-localization \n'
	print 'press control C to stop tool\n\n'

def DisplayStat(counter,target,ipcounter,tcpcounter, udpcounter, arpcounter):
	print "Total number of packets in the pcap file: ", counter
	if target not in  "":
		print "\n\nFiltered by " + target
		
	print "\nTotal number of ip packets: ", ipcounter
	print "Total number of tcp packets: ", tcpcounter
	print "Total number of udp packets: ", udpcounter
	print "Total number of arp packets: ", arpcounter
	print "Total number of DNS packets: ", dnscounter

	print "======================================"
	print "\nDest port:\n"
	
	
	for chiave in portlist:
		print "dst port = ", chiave, " packets ", portlist[chiave]

	print "======================================"
	
	print "\nTcp flags:\n"
	
	
	for chiave in flagstcp: 
		if isbadflag(chiave):
			print getFlag(chiave) + " packets ", flagstcp[chiave], " --> bad flag"	
		else:
			print getFlag(chiave) + " packets ", flagstcp[chiave]	
			
	print "======================================"
	
	print "\nIP Pack VS Flow:\n"
	Total = 0
	for x in IPSourceFlow.keys():
		Total += IPSourceFlow[x]

	
	for x in IPSourceFlow.keys():
		f  = get_Percent(IPSourceFlow[x], Total)
		print "Source IP: ",x," \tPackets number: ",IPSourceFlow[x],"\t%.2f" %f, "%"
				
	print "======================================"
	print "\nPacket of bad flags:\n"		
	
	i = 0
	while i < len(foundbadflag):
		print foundbadflag[i]
		i += 1
	print "======================================"
			
	print "\nDNS Query:\n"		
	
	i = 0
	while i < len(DNSquery):
		print DNSquery[i]
		i += 1			
		
	print "======================================"
	print "\nURL Request:\n"		
	i = 0
	
	while i < len(URL_Request):
		print URL_Request[i]
		i += 1					
	print "======================================"
	
	i = 0
	print "\nDangerous User-Agent:\n"	
	while i < len(UserAgent):
		print UserAgent[i]
		i += 1					
	print "======================================"
	
	print "\nPossible SQL Injection Attack:\n"	
	
	i = 0
	while i < len(SQL_Injection):
		print SQL_Injection[i]
		i += 1		
					
	print "======================================"

	print "\nPossible XSS Attack:\n"	
	
	i = 0
	while i < len(XSS):
		print XSS[i]
		i += 1					
	
	print "======================================"
	
	print "\nDownloads:\n"		
	i = 0
	
	while i < len(Attachment):
		print Attachment[i]
		i += 1		
						
def isbadflag(chiave):
   return chiave in badflags				

def get_Percent(Value, Total):
	return float(100 * float(Value) / float(Total)
	
	
	)
		   
def TCP_parse(pkt, counter):
	if isbadflag(pkt[TCP].flags):
		t = timeconverter(pkt.time)
		s = t, "  ", pkt.summary()
		foundbadflag.append(s)

	#parse if it is HTTP Response or Request
	c = pkt.getlayer(Raw)
	b= []
	a = str(c)
	b = a.split('\r\n')
	
	i = 0
	while i < len(b):
		d = b[i]
		#HTTP Request
		if d[0:3] == "GET" or d[0:4] == "POST" or d[0:7] == "OPTIONS" or d[0:4] == "HEAD" or d[0:3] == "PUT" or d[0:6] == "DELETE" or d[0:5] == "TRACE" or d[0:7] =="CONNECT":
			HTTP_parse(pkt.getlayer(Raw), counter)
		
		#HTTP Response
		if d[:7] == 'HTTP/1.': 
			HTTP_Response_parse(pkt.getlayer(Raw))
		i += 1
				
	if pkt[TCP].dport not in portlist:
		portlist[pkt[TCP].dport] = 1
	else:
		portlist[pkt[TCP].dport] = portlist[pkt[TCP].dport] + 1
	
	if pkt[TCP].flags not in flagstcp:
		flagstcp[pkt[TCP].flags] = 1
	else:
		flagstcp[pkt[TCP].flags] = flagstcp[pkt[TCP].flags] + 1
		
def UDP_parse(pkt):	
	if DNS in pkt[UDP]:
		#dnscounter += 1
		s = pkt[DNS].summary()
		if s[0:7] == "DNS Qry":
			#Insert only one time
			if s[9:-2] not in DNSquery:
				DNSquery.append(s[9:-2])

def IP_parse(pkt):
	IPlist.append(pkt[IP].src)
	IPlist.append(pkt[IP].dst)
	
	if pkt[IP].src not in IPSourceFlow:
		IPSourceFlow[pkt[IP].src] = 1
	else:
		IPSourceFlow[pkt[IP].src] = IPSourceFlow[pkt[IP].src] + 1
	
def HTTP_parse(payload, counter):
	b = []
	a = str(payload)
	
	b = a.split('\r\n')
	i = 0
	
	while i < len(b):
		c = b[i]
		if string.find(b[i], '%3Cscript%3E') > 0:
			XSS.append('Packets number: ' + str(counter) + ' - ' + b[i])

		d = c.split("%20")
		z = 0
		while z < len(d):	
			if d[z] == "UNION" or d[z] == "SELECT":
				SQL_Injection.append('Packets number: ' + str(counter) + ' - ' + b[i] + '\n')				
				break
			z += 1
		
		if c[0:5] == 'Host:':
			if b[i] not in URL_Request:
				URL_Request.append(b[i])
				exit
		if c[0:18] == 'User-Agent: sqlmap':
			if b[i] not in URL_Request:
				a = str(counter) + ' ' + b[i]
				UserAgent.append(a)
				exit
		i += 1

def HTTP_Response_parse(payload):
	b = []
	a = str(payload)
	
	b = a.split('\r\n')
	i = 0
	while i < len(b):
		c = b[i]
		if c[0:19] == 'Content-Disposition':	
			if b[i] not in Attachment:
				Attachment.append(b[i])
		i += 1
	
def getFlag(valore):
	result = ""
	if valore == 0:
		return "NULL"
		
	if valore & 1 == 1:
		result = result + " FIN"
		
	valore = valore >> 1
	
	if valore & 1 == 1:		
		result =  " SYN" + result
	valore = valore >> 1
	
	if valore & 1 == 1:		
		result =  " RST" + result
	valore = valore >> 1
	
	if valore & 1 == 1:		
		result =  " PSH" + result
	valore = valore >> 1
	
	if valore & 1 == 1:		
		result =  " ACK" + result
	valore = valore >> 1
	
	if valore & 1 == 1:		
		result =  "URG" + result
	valore = valore >> 1
	
	return result
	
def md5Checksum(filePath):
    with open(filePath, 'rb') as fh:
        m = hashlib.md5()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()

def googlegeoip():
	out_file = open("test.txt","w")
	i = 0
	while i < len(IPlist):
		out_file.write(IPlist[i] + '\r\n')
		i += 1
	out_file.close()
	a = []
	a = sys.path
	os.system('googlegeoip -f ' + a[0] + '/test.txt > test.html')
	os.system('firefox ' + a[0] + '/test.html')
	
def rebuild(pcap, rebuild_pcap):
	print "\n\nRebuild pcap file in " + rebuild_pcap
	a = []
	a = sys.path
	if os.path.exists(rebuild_pcap) == True:
		answer = raw_input("Path " + rebuild_pcap + " exists. Do you want overwrite it? ")
		print "answer = " + answer
		if answer == "y":
			shutil.rmtree(rebuild_pcap)
		else:
			exit()

	os.makedirs(rebuild_pcap)	
	os.system('tcpxtract -f ' + a[0] + "/" + pcap + ' -o ' + rebuild_pcap)

def get_usage():	
	print INFO
	print '\nUsage: python pcaparse.py -f nomefile.pcap -r -o folder\n'
	print '  -h, --help'
	print '    print these help informations\n'
	print '  -f, --file'
	print '    file pcap to analyze\n'
	print '  -v, --version'
	print '    print the software release\n'
	print '  -o, --output \n'
	print '    output folder for rebuild files \n'
	print '  -g, --geo \n'
	print '    use geo-localization \n'
	print 'press control C to stop tool\n\n'


def main(argv):
	geo = False
	if len(sys.argv) < 2:
		get_usage()
		exit()

	#analysis input parameter
	try:   
		opts, args = getopt.getopt(argv, "hgt:f:o:", ["help", "geo", "target=", "file=", "output="])          
	except getopt.GetoptError:
		get_usage()	
		sys.exit(1)
		
	target = ""
	filename = ""
	rebuild_pcap = ""

	for opt, arg in opts:
		if opt in ("-h", "--help"):
			get_usage()
			sys.exit()
			
		if opt in ("-t", "--target"):
			target = arg    
					
		if opt in ("-f", "--file"):
			file_parameter = True
			if os.path.exists(arg):
				print "Filename = " + arg
				print 'File size = ', os.path.getsize(arg)
				print "MD5 : ", md5Checksum(arg) 	
				filename = arg
			else:
				print "File " + arg + " does not exists!"
				sys.exit()	
		if opt in ("-g", "--geo"):
			geo = True	
		if opt in ("-o", "--output"):
			rebuild_pcap = arg
	
	if file_parameter == False:
		print"There isn't file pcap to analyze"
		exit()
	 	 		
	parsepcap(filename, target, geo, rebuild_pcap)
	
def timeconverter(value):	
	return datetime.datetime.fromtimestamp(int(value)).strftime('%Y-%m-%d %H:%M:%S')

if __name__ == "__main__":
	main(sys.argv[1:])
