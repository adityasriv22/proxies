#!/usr/bin/env python
from twisted.conch.telnet import TelnetTransport, TelnetProtocol,StatefulTelnetProtocol
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ServerEndpoint,TCP4ClientEndpoint
from time import gmtime, strftime, localtime
import os
import re
import MySQLdb
import ConfigParser
import geoip2.database
import collections
import json
from pyes import *
configParser = ConfigParser.RawConfigParser()   
configFilePath = 'proxy.conf'
configParser.read(configFilePath)



log_dir= configParser.get('telnet', 'log_dir')
client_addr=configParser.get('telnet', 'client_addr')
client_port=int(configParser.get('telnet', 'client_port'))
telnet_incoming_port = int(configParser.get('telnet', 'telnet_incoming_port'))
push_to_elasticsearch = int(configParser.get('elasticsearch', 'push_to_elasticsearch'))
if push_to_elasticsearch==1:
	es_host = configParser.get('elasticsearch', 'es_host')
	es_port = configParser.get('elasticsearch', 'es_port')
	es_username = configParser.get('elasticsearch', 'es_username')
	es_password = configParser.get('elasticsearch', 'es_password')
	tup1={'username':es_username,'password':es_password}
	es = ES(server=es_host+":"+es_port, basic_auth=tup1)



def es_connections_insert(ip,location,country,city,attack_time):
	auth_dict1 = collections.OrderedDict()
	auth_dict1['ip'] = ip
	auth_dict1['country'] = country
	auth_dict1['city'] = city
	auth_dict1['location'] = location
	auth_dict1['attack_time'] = attack_time
	auth_dict1['protocol'] = "telnet"
	auth_json = json.dumps(auth_dict1)
	print auth_json
	es.index(auth_json, 'attacks', 'connections')

def es_telnet_connections_insert(ip,location,country,city,attack_start_time,attack_end_time):
	auth_dict1 = collections.OrderedDict()
	auth_dict1['ip'] = ip
	auth_dict1['country'] = country
	auth_dict1['city'] = city
	auth_dict1['location'] = location
	auth_dict1['attack_start_time'] = attack_start_time
	auth_dict1['attack_end_time'] = attack_end_time
	auth_json = json.dumps(auth_dict1)
	print auth_json
	es.index(auth_json, 'attacks', 'telnet_connections')

def es_telnet_auth_details_insert(ip,username,password,time):
	auth_dict1 = collections.OrderedDict()
	auth_dict1['ip'] = ip
	auth_dict1['username'] = username
	auth_dict1['password'] = password
	auth_dict1['entered_time'] = time
	auth_json = json.dumps(auth_dict1)
	print auth_json
	es.index(auth_json, 'attacks', 'telnet_auth_details')

def get_ip_from_peer(string):
	comma_index=string.index('(')
	temp_string=string[comma_index+1:]
	temp_list = [x.strip() for x in temp_string.split(',')]
	return temp_list[1]


class TelnetClientProtocol(StatefulTelnetProtocol):
	
	def connectionLost(self, reason):
		print "Connection lost"
	
	def connectionMade(self):
		self.factory.originator.originator2=self

	def dataReceived(self, line):
		if re.search('([Ll]ogin:\s+$)', line):
			self.factory.originator.user_set=0
			self.factory.originator.password_set=0
			self.factory.originator.user=""
			self.factory.originator.password=""
		
		self.factory.originator.forwardLine(line)
		
		
	def forwardData(self,line):
		self.transport.write(line)


		
class TelnetClientFactory(Factory):
	protocol=TelnetClientProtocol
	
	def __init__(self):
		print "Initialized factory"
		
class TelnetServerProtocol(StatefulTelnetProtocol):
	
	def __init__(self):
	
		self.temp_factory=TelnetClientFactory()
		self.user=""
		self.password=""
		self.attacker_ip=""
		self.user_set=0
		self.password_set=0
		self.connection_setup=0
		self.fil = open("dummy.tmp","w+")
		self.fil1 = open("dummy1.tmp","w+")
		self.new_line=1
		self.starting_time=""
		self.ending_time=""
		self.location=""
		self.country=""
		self.city=""
		self.fil.close()
		self.fil1.close()


	def connectionLost(self, reason):
		self.ending_time=strftime("%d %b %Y %H:%M:%S", localtime())
		print "Connection lost"
		if push_to_elasticsearch==1:
			es_telnet_connections_insert(self.attacker_ip,self.location,self.country,self.city,self.starting_time,self.ending_time)
		self.fil.close()
		self.fil1.close()

	
	def dataReceived(self, line):
		proto=self.originator2
		proto.forwardData(line)
		i=0
		if self.new_line==1:
			self.fil.write(strftime("\n"+"%d %b %Y %H:%M:%S", localtime())+": ")
			self.fil1.write(strftime("\n"+"%d %b %Y %H:%M:%S", localtime())+": ")
			self.new_line=0
		if self.connection_setup==0:
			self.connection_setup=1
		else:
			while i<len(line):
				self.fil1.write(line[i])
				if (ord(line[i]) > 31 and ord(line[i]) < 128) or (ord(line[i])==13):
					self.fil.write(line[i])
					if not(self.user_set==2 and self.password_set==2):
						if self.user_set==0:
							if ord(line[i])==13:
								self.user_set=2
							else:
								self.user_set=1
								self.user=self.user+line[i]
						elif self.user_set==1:	
					
							if ord(line[i])==13:
								self.user_set=2
							else:
								self.user=self.user+line[i]
						elif self.user_set==2:
							if self.password_set==0:
								if ord(line[i])==13:
									self.password_set=2
									if len(self.user)!=0 and self.user[0]=='P':
										self.user=self.user[1:]
									if push_to_elasticsearch==1:
										es_telnet_auth_details_insert(self.attacker_ip,self.user,self.password,strftime("%d %b %Y %H:%M:%S", localtime()))
								else:
									self.password_set=1
									self.password=self.password+line[i]
							elif self.password_set==1:
								if ord(line[i])==13:
									self.password_set=2
									if len(self.user)!=0 and self.user[0]=='P':
										self.user=self.user[1:]
									if push_to_elasticsearch==1:
										es_telnet_auth_details_insert(self.attacker_ip,self.user,self.password,strftime("%d %b %Y %H:%M:%S", localtime()))
								else:
									self.password=self.password+line[i]
						
				if ord(line[i])==13:
					self.new_line=1
				i=i+1
		
	
	def connectionMade(self):
		self.user_set=2
		self.password_set=2
		self.starting_time=strftime("%d %b %Y %H:%M:%S", localtime())
		print "attacker connection from", self.transport.getPeer()
		self.attacker_ip=self.attacker_ip+get_ip_from_peer(str(self.transport.getPeer()))
		self.attacker_ip=self.attacker_ip[1:-1]
		self.temp_factory.originator = self
		if not os.path.isdir(log_dir+"/"+self.attacker_ip):
			os.mkdir(log_dir+"/"+self.attacker_ip)
		
		self.fil=open(log_dir+"/"+self.attacker_ip+"/"+strftime("%d:%b:%Y:%H:%M:%S", localtime()),"w+")
		self.fil1=open(log_dir+"/"+self.attacker_ip+"/"+strftime("%d:%b:%Y:%H:%M:%S", localtime())+"_raw","w+")
		reader = geoip2.database.Reader("GeoLite2-City.mmdb")
		try:
			rez = reader.city(self.attacker_ip)

			self.country=rez.country.name
			self.city=rez.city.name
			self.location=str(rez.location.latitude)+","+str(rez.location.longitude)
			
			
		except:
			print "not found"
		
		self.fil.write("connection from " + self.attacker_ip)
		self.fil1.write("connection from " + self.attacker_ip)
		
		try:
			self.fil.write("\n Location Details: " + self.location + ", " + self.city + ", " + self.country + " \n")
			self.fil1.write("\n Location Details: " + self.location + ", " + self.city + ", " + self.country + " \n") 
		except:
			print "location not found"	
		if push_to_elasticsearch==1:
			es_connections_insert(self.attacker_ip,self.location,self.country,self.city,self.starting_time)
		client_endpoint = TCP4ClientEndpoint(reactor,client_addr,client_port)
		client_endpoint.connect(self.temp_factory)
	
	def forwardLine(self, line):
		self.transport.write(line)
	


class TelnetServerFactory(Factory):
	protocol=TelnetServerProtocol
	def __init__(self):
		print "Initialized factory"


def main():
	if push_to_elasticsearch==1:
		try:
			es.indices.create_index("attacks")
		except:
			print "already there"
	
	mapping = {
	     'ip': {
		 'store': 'yes',
		 'type': 'keyword',
	     },
	     'username': {
		 'store': 'yes',
		 'type': 'keyword',
	     },
	     'password': {
		 'store': 'yes',
		 'type': 'keyword',
	     },
	     'entered_time': {
		 'store': 'yes',
		 'type': 'date',
		 'format' : 'dd MMM yyyy HH:mm:ss'
	     }
	}
	if push_to_elasticsearch==1:
		es.indices.put_mapping("telnet_auth_details", {'properties':mapping}, ["attacks"])

	mapping = {
	     'ip': {
		 'store': 'yes',
		 'type': 'keyword',
	     },
	     'country': {
		 'store': 'yes',
		 'type': 'keyword',
	     },
	     'location': {
		 'store': 'yes',
		 'type': 'geo_point',
	     },
	     'attack_start_time': {
		 'store': 'yes',
		 'type': 'date',
		 'format' : 'dd MMM yyyy HH:mm:ss'
	     },
	     'attack_end_time': {
		 'store': 'yes',
		 'type': 'date',
		 'format' : 'dd MMM yyyy HH:mm:ss'
	     }
	}
	if push_to_elasticsearch==1: 
		es.indices.put_mapping("telnet_connections", {'properties':mapping}, ["attacks"])
	
	mapping = {
	     'ip': {
		 'store': 'yes',
		 'type': 'keyword',
	     },
	     'country': {
		 'store': 'yes',
		 'type': 'keyword',
	     },
	     'location': {
		 'store': 'yes',
		 'type': 'geo_point',
	     },
	     'attack_time': {
		 'store': 'yes',
		 'type': 'date',
		 'format' : 'dd MMM yyyy HH:mm:ss'
	     },
	     'protocol': {
		 'store': 'yes',
		 'type': 'keyword',
	     }
	}
	if push_to_elasticsearch==1: 
		es.indices.put_mapping("connections", {'properties':mapping}, ["attacks"])
	
	server_endpoint = TCP4ServerEndpoint(reactor, telnet_incoming_port)
	
	server_endpoint.listen(TelnetServerFactory())
	reactor.run()

main()

