# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

from twisted.internet import reactor
from twisted.web import proxy, server
from twisted.web.resource import Resource
from twisted.python.compat import urllib_parse, urlquote
from twisted.web.server import NOT_DONE_YET
from twisted.web.http import proxiedLogFormatter
from time import gmtime, strftime, localtime
import os
import re
import ConfigParser
import geoip2.database
import pony.orm
import pony.options
import collections
import json
from pyes import *
configParser = ConfigParser.RawConfigParser()   
configFilePath = 'proxy.conf'
configParser.read(configFilePath)
log_dir= configParser.get('http', 'log_dir')
client_addr=configParser.get('http', 'client_addr')
client_port=int(configParser.get('http', 'client_port'))
http_incoming_port = int(configParser.get('http', 'http_incoming_port'))
push_to_elasticsearch = int(configParser.get('elasticsearch', 'push_to_elasticsearch'))
if push_to_elasticsearch==1:
	es_host = configParser.get('elasticsearch', 'es_host')
	es_port = configParser.get('elasticsearch', 'es_port')
	es_username = configParser.get('elasticsearch', 'es_username')
	es_password = configParser.get('elasticsearch', 'es_password')
	tup1={'username':es_username,'password':es_password}
	es = ES(server=es_host+":"+es_port, basic_auth=tup1)



class MyReverseProxyResource(proxy.ReverseProxyResource):
	proxyClientFactoryClass = proxy.ProxyClientFactory


	def __init__(self, host, port, path, reactor=reactor):
		Resource.__init__(self)
		self.host = host
		self.port = port
		self.path = path
		self.reactor = reactor


	def getChild(self, path, request):
		request_time=strftime("%d %b %Y %H:%M:%S", localtime())
		reader = geoip2.database.Reader("GeoLite2-City.mmdb")
		country=""
		city=""
		location=""
		try:
			rez = reader.city(str(request. getClientIP()))

			country=rez.country.name
			city=rez.city.name
			location=str(rez.location.latitude)+","+str(rez.location.longitude)
			
			
		except:
			print "not found"
		
		fil=open(log_dir+"/"+str(request. getClientIP()),"a")
		fil.write("\n\n"+request_time)
		fil.write(":connection from " + str(request. getClientIP()) + "\n")
		try:
			fil.write("\n  Location Details: " + location + ", " + city + ", " + country + " \n") 
		except:
			print "location not found"	
		#fil.write("\n request:" + str(request))
		fil.write("\n  request method:"+request.method)
		fil.write("\n  request.uri:" + str(request.uri))
		fil.write("\n  request.path:" + str(request.path))
		fil.write("\n  request args" + str(request.args))
		fil.write("\n  request headers:" + str(request.requestHeaders))
		fil.write("\n  response headers:" + str(request.responseHeaders))
		#fil.close()
		if push_to_elasticsearch==1:
			auth_dict = collections.OrderedDict()
	    		auth_dict['ip'] = request.getClientIP()
			auth_dict['country'] = country
			auth_dict['city'] = country
			auth_dict['location'] = location
			auth_dict['attack_time'] = request_time
			auth_dict['request_method'] = str(request.method)
			auth_dict['request_uri'] = str(request.uri)
			auth_dict['request_path'] = str(request.path)
			auth_dict['request_args'] = str(request.args)
			auth_dict['request_headers'] = str(request.requestHeaders)
			auth_dict['response_headers'] = str(request.responseHeaders)
	    		auth_json = json.dumps(auth_dict)
	    		print auth_json
	    		es.index(auth_json, 'attacks', 'http_requests')
			auth_dict1 = collections.OrderedDict()
	    		auth_dict1['ip'] = request.getClientIP()
			auth_dict1['country'] = country
			auth_dict1['city'] = city
			auth_dict1['location'] = location
			auth_dict1['attack_time'] = request_time
			auth_dict1['protocol'] = "http"
			auth_json = json.dumps(auth_dict1)
	    		print auth_json
	    		es.index(auth_json, 'attacks', 'connections')
		fil.close()
		
		return proxy.ReverseProxyResource(
            	self.host, self.port, self.path + b'/' + urlquote(path, safe=b"").encode('utf-8'),
            	self.reactor)


	def render(self, request):
		"""
		Render a request by forwarding it to the proxied server.
		"""
		
		
        # RFC 2616 tells us that we can omit the port if it's the default port,
        # but we have to provide it otherwise
        	if self.port == 80:
            		host = self.host
        	else:
            		host = self.host + u":" + str(self.port)
		request.requestHeaders.setRawHeaders(b"host", [host.encode('ascii')])
		request.content.seek(0, 0)
		qs = urllib_parse.urlparse(request.uri)[4]
		if qs:
		    rest = self.path + b'?' + qs
		else:
		    rest = self.path
		clientFactory = self.proxyClientFactoryClass(
		    request.method, rest, request.clientproto,
		    request.getAllHeaders(), request.content.read(), request)
		self.reactor.connectTCP(self.host, self.port, clientFactory)
		return NOT_DONE_YET

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
     'country': {
         'store': 'yes',
         'type': 'keyword',
     },
     'city': {
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
     'request_method': {
         'store': 'yes',
         'type': 'keyword',
     },
     'request_uri': {
         'store': 'yes',
         'type': 'keyword',
     },
     'request_path': {
         'store': 'yes',
         'type': 'keyword',
     },
     'request_args': {
         'store': 'yes',
         'type': 'keyword',
     },
     'request_headers': {
         'store': 'yes',
         'type': 'keyword',
     },
     'response_headers': {
         'store': 'yes',
         'type': 'keyword',
     }


}
if push_to_elasticsearch==1:
	es.indices.put_mapping("http_requests", {'properties':mapping}, ["attacks"])

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

site = server.Site(MyReverseProxyResource(client_addr, client_port, ''))
reactor.listenTCP(http_incoming_port, site)
reactor.run()
