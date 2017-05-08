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
log_dir= configParser.get('cwmp', 'log_dir')
client_addr=configParser.get('cwmp', 'client_addr')
client_port=int(configParser.get('cwmp', 'client_port'))
cwmp_incoming_port = int(configParser.get('cwmp', 'cwmp_incoming_port'))
push_to_elasticsearch = int(configParser.get('elasticsearch', 'push_to_elasticsearch'))
if push_to_elasticsearch==1:
	es_host = configParser.get('elasticsearch', 'es_host')
	es_port = configParser.get('elasticsearch', 'es_port')
	es_username = configParser.get('elasticsearch', 'es_username')
	es_password = configParser.get('elasticsearch', 'es_password')
	tup1={'username':es_username,'password':es_password}
	es = ES(server=es_host+":"+es_port, basic_auth=tup1)


def cwmp_parse(text_inst):
	text=str(text_inst)
	return_text=""
	return_command=""
	if not(text):
		return [return_text,return_command]
	if re.search("cwmp:InformResponse",text):
		return_text=return_text+"inform response\n"
		return_command="InformResponse"
	
	if re.search("cwmp:SetParameterValues",text):
		return_command="SetParameterValues"
		return_text=return_text+"Setting Parameters\n"
		struct=re.findall(r'<ParameterValueStruct>(.*?)</ParameterValueStruct>',text,re.DOTALL)
		for pair in struct:
			terms=re.findall(r'<Name>(.*?)</Name>',pair,re.DOTALL)
			temp_values=re.findall(r'<Value(.*?)</Value>',pair,re.DOTALL)
			values=[]
			i=0
			while i < len(temp_values):
				before_keyword, keyword, after_keyword = temp_values[i].partition('>')
				return_text=return_text+terms[i]+" to "+after_keyword+"\n"
				i=i+1
		return_text=return_text+"Parameter Key:"+(re.findall(r'<ParameterKey>(.*?)</ParameterKey>',text,re.DOTALL))[0]+"\n"
		
	if re.search("cwmp:GetParameterValues",text):
		return_command="GetParameterValues"
		return_text=return_text+"Getting Parameters\n"
		terms=re.findall(r'<string>(.*?)</string>',text,re.DOTALL)
		for term in terms:
			return_text=return_text+"term\n"	

	if re.search("cwmp:GetRPCMethods",text):
		return_command="GetRPCMethods"
		return_text=return_text+"Getting RPC Methods\n"

	if re.search("cwmp:GetParameterNames",text):
		return_command="GetParameterNames"
		return_text=return_text+"Getting Parameter Names\n"
		parameter_path=re.findall(r'<ParameterPath>(.*?)</ParameterPath>',text,re.DOTALL)
		next_level=re.findall(r'<NextLevel>(.*?)</NextLevel>',text,re.DOTALL)
		i=0
		while i<len(parameter_path):
			return_text=return_text+"parameter path:"+parameter_path[i]+"\nnext level:"+next_level[i]+"\n"
			i=i+1


	if re.search("cwmp:AddObject",text):
		return_command="AddObject"
		return_text=return_text+"Adding object\n"
		objects=re.findall(r'<ObjectName>(.*?)</ObjectName>',text,re.DOTALL)
		parameter_keys=re.findall(r'<ParameterKey>(.*?)</ParameterKey>',text,re.DOTALL)
		i=0
		while i<len(objects):
			return_text=return_text+"object:"+objects[i]+"\n"
			if i< len(parameter_keys):
				return_text=return_text+"parameter keys:"+parameter_keys[i]+"\n"
			i=i+1
	
	if re.search("cwmp:DeleteObject",text):
		return_command="DeleteObject"
		return_text=return_text+"Deleting object\n"
		objects=re.findall(r'<ObjectName>(.*?)</ObjectName>',text,re.DOTALL)
		parameter_keys=re.findall(r'<ParameterKey>(.*?)</ParameterKey>',text,re.DOTALL)
		i=0
		while i<len(objects):
			return_text=return_text+"object:"+objects[i]+"\n"
			if i< len(parameter_keys):
				return_text=return_text+"parameter keys:"+parameter_keys[i]+"\n"
			i=i+1

	if re.search("cwmp:SetParameterAttributes",text):
		return_command="SetParameterAttributes"
		return_text=return_text+"Setting Parameter Attributes \n"
		struct=re.findall(r'<SetParameterAttributesStruct>(.*?)</SetParameterAttributesStruct>',text,re.DOTALL)
		for pair in struct:
			names=re.findall(r'<Name>(.*?)</Name>',pair,re.DOTALL)
			if names:
				return_text=return_text+"Name:"+names[0]+"\n"
			notification_changes=re.findall(r'<NotificationChange>(.*?)</NotificationChange>',pair,re.DOTALL)
			if notification_changes:
				return_text=return_text+"Notification changes:"+notification_changes[0]+"\n"
			notification=re.findall(r'<Notification>(.*?)</Notification>',pair,re.DOTALL)
			if notification:
				return_text=return_text+"Notification:"+notification[0]+"\n"
			access_list_change=re.findall(r'<AccessListChange>(.*?)</AccessListChange>',pair,re.DOTALL)
			if access_list_change:
				return_text=return_text+"Access List Changes:"+access_list_change[0]+"\n"
			access_list=re.findall(r'<AccessList>(.*?)</AccessList>',pair,re.DOTALL)
			if access_list:
				return_text=return_text+"Access List\n"
				access_list_members=re.findall(r'<string>(.*?)</string>',access_list[0],re.DOTALL)
				for member in access_list_members:
					return_text=return_text+member+"\n"
			
	
	if re.search("cwmp:GetParameterAttributes",text):
		return_command="GetParameterAttributes"
		return_text=return_text+"Getting Parameter Attributes\n"
		terms=re.findall(r'<string>(.*?)</string>',text,re.DOTALL)
		for member in terms:
					return_text=return_text+member+"\n"

	if re.search("cwmp:Download",text):
		return_command="Download"
		return_text=return_text+"Download \n"
		terms=re.findall(r'<CommandKey>(.*?)</CommandKey>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Command Key:"+terms[0]+"\n"
		terms=re.findall(r'<FileType>(.*?)</FileType>',text,re.DOTALL)
		if terms:
			return_text=return_text+"File Type:"+terms[0]+"\n"
		terms=re.findall(r'<URL>(.*?)</URL>',text,re.DOTALL)
		if terms:
			return_text=return_text+"URL:"+terms[0]+"\n"
		terms=re.findall(r'<Username>(.*?)</Username>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Username:"+terms[0]+"\n"
		terms=re.findall(r'<Password>(.*?)</Password>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Password:"+terms[0]+"\n"
		terms=re.findall(r'<FileSize>(.*?)</FileSize>',text,re.DOTALL)
		if terms:
			return_text=return_text+"File Size:"+terms[0]+"\n"
		terms=re.findall(r'<DelaySeconds>(.*?)</DelaySeconds>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Delay Seconds:"+terms[0]+"\n"
		terms=re.findall(r'<SuccessURL>(.*?)</SuccessURL>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Success URL:"+terms[0]+"\n"
		terms=re.findall(r'<FailureURL>(.*?)</FailureURL>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Failure URL:"+terms[0]+"\n"
		terms=re.findall(r'<TargetFileName>(.*?)</TargetFileName>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Target File Name:"+terms[0]+"\n"

	if re.search("cwmp:Reboot",text):
		return_command="Reboot"
		return_text=return_text+"Reboot \n"
		terms=re.findall(r'<CommandKey>(.*?)</CommandKey>',text,re.DOTALL)
		return_text=return_text+"Command Key"+terms[0]+"\n"
	if re.search("cwmp:GetQueuedTransfers",text):
		return_command="GetQueuedTransfers"
		return_text=return_text+"Get Queued Transfers \n"
	if re.search("cwmp:ScheduleInform",text):
		return_command="ScheduleInform"
		return_text=return_text+"Schedule Inform \n"
		terms=re.findall(r'<DelaySeconds>(.*?)</DelaySeconds>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Delay Seconds:"+terms[0]+"\n"
		terms=re.findall(r'<CommandKey>(.*?)</CommandKey>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Command Key:"+terms[0]+"\n"
	if re.search("cwmp:SetVouchers",text):
		return_command="SetVouchers"
		return_text=return_text+"Setting vouchers\n"
		terms=re.findall(r'<base64>(.*?)</base64>',text,re.DOTALL)
		for member in terms:
					return_text=return_text+member+"\n"
	if re.search("cwmp:GetOptions",text):
		return_command="GetOptions"
		return_text=return_text+"Get Options\n"
		terms=re.findall(r'<OptionName>(.*?)</OptionName>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Option Name:"+terms[0]+"\n"
	if re.search("cwmp:Upload",text):
		return_command="Upload"
		return_text=return_text+"Upload \n"
		terms=re.findall(r'<CommandKey>(.*?)</CommandKey>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Command Key:"+terms[0]+"\n"
		terms=re.findall(r'<FileType>(.*?)</FileType>',text,re.DOTALL)
		if terms:
			return_text=return_text+"File Type:"+terms[0]+"\n"
		terms=re.findall(r'<URL>(.*?)</URL>',text,re.DOTALL)
		if terms:
			return_text=return_text+"URL:"+terms[0]+"\n"
		terms=re.findall(r'<Username>(.*?)</Username>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Username:"+terms[0]+"\n"
		terms=re.findall(r'<Password>(.*?)</Password>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Password:"+terms[0]+"\n"
		terms=re.findall(r'<DelaySeconds>(.*?)</DelaySeconds>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Delay Seconds:"+terms[0]+"\n"
		
	if re.search("cwmp:FactoryReset",text):
		return_command="FactoryReset"
		return_text=return_text+"Factory Reset\n"
	
	if re.search("cwmp:GetAllQueuedTransfers",text):
		return_command="GetAllQueuedTransfers"
		return_text=return_text+"Get All Queued Transfers\n"
	
	if re.search("cwmp:ScheduleDownload",text):
		return_command="ScheduleDownload"
		return_text=return_text+"Schedule Download \n"
		terms=re.findall(r'<CommandKey>(.*?)</CommandKey>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Command Key:"+terms[0]+"\n"
		terms=re.findall(r'<FileType>(.*?)</FileType>',text,re.DOTALL)
		if terms:
			return_text=return_text+"File Type:"+terms[0]+"\n"
		terms=re.findall(r'<URL>(.*?)</URL>',text,re.DOTALL)
		if terms:
			return_text=return_text+"URL:"+terms[0]+"\n"
		terms=re.findall(r'<Username>(.*?)</Username>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Username:"+terms[0]+"\n"
		terms=re.findall(r'<Password>(.*?)</Password>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Password:"+terms[0]+"\n"
		terms=re.findall(r'<FileSize>(.*?)</FileSize>',text,re.DOTALL)
		if terms:
			return_text=return_text+"File Size:"+terms[0]+"\n"
		terms=re.findall(r'< TargetFileName>(.*?)</ TargetFileName>',text,re.DOTALL)
		if terms:
			return_text=return_text+" Target File Name:"+terms[0]+"\n"
		terms=re.findall(r'<TimeWindowList>(.*?)</TimeWindowList>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Time Window List:"+"\n"
			terms1=re.findall(r'<WindowStart>(.*?)</WindowStart>',terms[0],re.DOTALL)
			if terms1:
				return_text=return_text+"Window Start:"+terms1[0]+"\n"
			terms1=re.findall(r'<WindowEnd>(.*?)</WindowEnd>',terms[0],re.DOTALL)
			if terms1:
				return_text=return_text+"Window End:"+terms1[0]+"\n"
			terms1=re.findall(r'<WindowMode>(.*?)</WindowMode>',terms[0],re.DOTALL)
			if terms1:
				return_text=return_text+"Window Mode:"+terms1[0]+"\n"
			terms1=re.findall(r'<UserMessage>(.*?)</UserMessage>',terms[0],re.DOTALL)
			if terms1:
				return_text=return_text+"User Message:"+terms1[0]+"\n"
			terms1=re.findall(r'<MaxRetries>(.*?)</MaxRetries>',terms[0],re.DOTALL)
			if terms1:
				return_text=return_text+"Max Retries:"+terms1[0]+"\n"

	if re.search("cwmp:CancelTransfer",text):
		return_command="CancelTransfer"
		return_text=return_text+"Cancel Transfer\n"
		terms=re.findall(r'<CommandKey>(.*?)</CommandKey>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Command Key:"+terms[0]+"\n"

	if re.search("cwmp:ChangeDUState",text):
		return_command="ChangeDUState"
		return_text=return_text+"Change DU State\n"
		terms=re.findall(r'<CommandKey>(.*?)</CommandKey>',text,re.DOTALL)
		if terms:
			return_text=return_text+"Command Key:"+terms[0]+"\n"
		terms=re.findall(r'<InstallOpStruct>(.*?)</InstallOpStruct>',text,re.DOTALL)
		i=0
		while i<len(terms):
			return_text=return_text+"Install Op Struct:"+"\n"
			terms1=re.findall(r'<URL>(.*?)</URL>',terms[i],re.DOTALL)
			if terms1:
				return_text=return_text+"URL:"+terms1[0]+"\n"
			terms1=re.findall(r'<UUID>(.*?)</UUID>',terms[i],re.DOTALL)
			if terms1:
				return_text=return_text+"UUID:"+terms1[0]+"\n"
			terms1=re.findall(r'<Username>(.*?)</Username>',terms[i],re.DOTALL)
			if terms1:
				return_text=return_text+"Username:"+terms1[0]+"\n"
			terms1=re.findall(r'<Password>(.*?)</Password>',terms[i],re.DOTALL)
			if terms1:
				return_text=return_text+"Password:"+terms1[0]+"\n"
			terms1=re.findall(r'<ExecutionEnvRef>(.*?)</ExecutionEnvRef>',terms[i],re.DOTALL)
			if terms1:
				return_text=return_text+"Execution Env Ref:"+terms[0]+"\n"

			i=i+1
		terms=re.findall(r'<UnInstallOpStruct>(.*?)</UnInstallOpStruct>',text,re.DOTALL)
		i=0
		while i<len(terms):
			return_text=return_text+"Uninstall Op Struct:"+"\n"
			terms1=re.findall(r'<UUID>(.*?)</UUID>',terms[i],re.DOTALL)
			if terms1:
				return_text=return_text+"UUID:"+terms1[0]+"\n"
			terms1=re.findall(r'<Version>(.*?)</Version>',terms[i],re.DOTALL)
			if terms1:
				return_text=return_text+"Version:"+terms1[0]+"\n"
			terms1=re.findall(r'<ExecutionEnvRef>(.*?)</ExecutionEnvRef>',terms[i],re.DOTALL)
			if terms1:
				return_text=return_text+"Execution Env Ref:"+terms[0]+"\n"

			i=i+1
		terms=re.findall(r'<UpdateOpStruct>(.*?)</UpdateOpStruct>',text,re.DOTALL)
		i=0
		while i<len(terms):
			return_text=return_text+"Update Op Struct:"+"\n"
			terms1=re.findall(r'<URL>(.*?)</URL>',terms[i],re.DOTALL)
			if terms1:
				return_text=return_text+"URL:"+terms1[0]+"\n"
			terms1=re.findall(r'<UUID>(.*?)</UUID>',terms[i],re.DOTALL)
			if terms1:
				return_text=return_text+"UUID:"+terms1[0]+"\n"
			terms1=re.findall(r'<Username>(.*?)</Username>',terms[i],re.DOTALL)
			if terms1:
				return_text=return_text+"Username:"+terms1[0]+"\n"
			terms1=re.findall(r'<Password>(.*?)</Password>',terms[i],re.DOTALL)
			if terms1:
				return_text=return_text+"Password:"+terms1[0]+"\n"
			terms1=re.findall(r'<Version>(.*?)</Version>',terms[i],re.DOTALL)
			if terms1:
				return_text=return_text+"Version:"+terms[0]+"\n"

			i=i+1
			
		
	return [return_text,return_command]


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
		fil=open(log_dir+"/http_"+str(request. getClientIP()),"a")
		fil_cwmp=open(log_dir+"/cwmp_"+str(request. getClientIP()),"a")


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
		fil.write("\n  request args:" + str(request.args))
		fil.write("\n  request headers:" + str(request.requestHeaders))
		fil.write("\n  response headers:" + str(request.responseHeaders))
		#fil.close()
		
		fil_cwmp.write("\n\n"+request_time)
		fil_cwmp.write(":connection from " + str(request. getClientIP()) + "\n")
		try:
			fil_cwmp.write("\n  Location Details: " + location + ", " + city + ", " + country + " \n") 
		except:
			print "location not found"	
		[return_text,return_command]=cwmp_parse(request.args)
		if return_text=="":
			fil_cwmp.write("\n\n"+request_time+": Unable to process the cwmp request. Check the http logs")
		else:
			fil_cwmp.write("\n\n"+request_time+"\n"+return_text)
		if push_to_elasticsearch==1:
			auth_dict = collections.OrderedDict()
	    		auth_dict['ip'] = request.getClientIP()
			auth_dict['country'] = country
			auth_dict['city'] = city
			auth_dict['location'] = location
			auth_dict['attack_time'] = request_time
			auth_dict['request_method'] = return_command
			auth_json = json.dumps(auth_dict)
	    		print auth_json
	    		es.index(auth_json, 'attacks', 'cwmp_requests')
			auth_dict1 = collections.OrderedDict()
	    		auth_dict1['ip'] = request.getClientIP()
			auth_dict1['country'] = country
			auth_dict1['city'] = city
			auth_dict1['location'] = location
			auth_dict1['attack_time'] = request_time
			auth_dict1['protocol'] = "cwmp"
			auth_json = json.dumps(auth_dict1)
	    		print auth_json
	    		es.index(auth_json, 'attacks', 'connections')
		fil.close()
		fil_cwmp.close()
		
		return proxy.ReverseProxyResource(
            	self.host, self.port, self.path + b'/' + urlquote(path, safe=b"").encode('utf-8'),
            	self.reactor)


	def render(self, request):
		"""
		Render a request by forwarding it to the proxied server.
		"""
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
     'cwmp_method': {
         'store': 'yes',
         'type': 'keyword',
     }

}
if push_to_elasticsearch==1:
	es.indices.put_mapping("cwmp_requests", {'properties':mapping}, ["attacks"])

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
reactor.listenTCP(cwmp_incoming_port, site)
reactor.run()
