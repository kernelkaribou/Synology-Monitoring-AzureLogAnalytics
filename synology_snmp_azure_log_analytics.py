#!/bin/python

#########################################################################################################
# Author: Kernelkaribou
#
# Script captures SNMP data from a synology NAS and sends it to Azure Log Analytics to be reviewed.
# The submission logic was taken from the HTTP API for Log Analytics, Python Sample:
# https://docs.microsoft.com/en-us/azure/azure-monitor/platform/data-collector-api#sample-requests
# Script is free to use however you want
#########################################################################################################

from subprocess import check_output
import requests
import json
import datetime
import hashlib
import hmac
import base64
import re
import math


##################
######Config######
##################


host_address = "localhost" #NAS IP, suggest to run directly on NAS but can be remote 
hostname = "" #Leave blank if you want it to pull from the NAS itself, otherwise it can be defined here.

#Stats to Capture, set to false for metrics not desired, true to be captured
capture_system_temperature = "true"
capture_cpu = "true"
capture_memory = "true"
capture_network = "true"
capture_volume = "true"
capture_disk = "true"
capture_ups = "true"
ups_name = "" #Leave blank if you want to have it be the hostname of the NAS, otherwise you customize it here

# This is your Log Analytics workspace ID
workspace_id = "xxxxxxxx-xxx-xxx-xxx-xxxxxxxxxxxx"

# For the shared key, use either the primary or the secondary Connected Sources client authentication key   
shared_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# The log type is the name of the event that is being submitted. _CL is appended by Azure to whatever value is set here. You will query the below value + '_CL'
log_type = 'SynoMon'

#####################
######Functions######  
#####################

#Function to pull the SNMP Stats based upon OID and flags
def get_snmp_data(host_address, oid, snmpwalk_flags):

	snmp_data = check_output(["snmpwalk", "-v", "2c", "-c", "public", host_address, oid, "-O", snmpwalk_flags]).decode("utf-8").replace("\"","").replace('\r', "").split('\n')
	snmp_data = list(filter(None, snmp_data)) #Remove Empty entries from split
	return snmp_data

#Function to build List of metrics for a data point
def build_counter_list(hostname, object_name, counter_name, instance_name, counter_value, counter_type):

    counter_list = ({"Computer" : hostname, "ObjectName" : object_name, "CounterName" : counter_name, "InstanceName" : instance_name , "CounterValue" : counter_value, "Type" : counter_type})
    return counter_list

#Function to get instance name and ID for SNMP stats of multiple data points e.g. volumes or Disks
def get_snmp_instances(snmp_data):
        
	instance_name = snmp_data.rsplit('STRING: ', 1)[-1]
	instance_id = snmp_data.rsplit('.', 1)[-1].split(" = STRING")[0] 
	snmp_instances = {"name" : instance_name, "id" : instance_id}
	return snmp_instances

def get_instance_value(oid, oid_dump, data_type):
	
	#Iterate through SNMP MIB data and find matching OID for a specific instance
	idx = [i for i, item in enumerate(oid_dump) if re.search(oid, item)][0]
	instance_value = oid_dump[idx].rsplit(': ', 1)[-1].split(" ")[0]
	if data_type == "int":
		instance_value = int(instance_value)
	elif data_type == "str":
		instance_value = str(instance_value)
	elif data_type == "percent":
		instance_value = int(float(instance_value))
	return instance_value


#Getting System Temperature
def get_system_temperature():
	object_name = "System"
	instance_name = "System Temperature"
	counter_type = "Status"
	
	oid_system_temp = "1.3.6.1.4.1.6574.1.2"
	snmpwalk_flags = "qv"
	counter_value = get_snmp_data(host_address, oid_system_temp, snmpwalk_flags)
	system_temp = int(counter_value[0])
	counter_name = "Temperature"
	snmp_data.append(build_counter_list(hostname, object_name, counter_name, instance_name, system_temp, counter_type))


#Getting CPU Usage
def get_cpu_counters():
	object_name = "Processor"
	instance_name = "_Total"
	counter_type = "Perf"
	
	oid_processor = "1.3.6.1.4.1.2021.11.11.0"
	snmpwalk_flags = "qv"
	counter_value = get_snmp_data(host_address, oid_processor, snmpwalk_flags)
	processor_load =  100 - int(counter_value[0])
	counter_name = "% Processor Time"
	snmp_data.append(build_counter_list(hostname, object_name, counter_name, instance_name, processor_load, counter_type))



#Getting Memory Information (this requires gathering multiple metrics for calculation)
def get_memory_counters():
	object_name = "Memory"
	instance_name = "Memory"
	counter_type = "Perf"
	memory_oid = "1.3.6.1.4.1.2021.4"
	snmpwalk_flags = "n"
	memory_data = get_snmp_data(host_address, memory_oid, snmpwalk_flags)
	
	oid_memory_total = "1.3.6.1.4.1.2021.4.5.0"
	memory_total = get_instance_value(oid_memory_total, memory_data, "int")
	
	oid_memory_avail = "1.3.6.1.4.1.2021.4.6.0"
	memory_avail = get_instance_value(oid_memory_avail, memory_data, "int")
		
	oid_memory_buffer = "1.3.6.1.4.1.2021.4.14.0"
	memory_buffer = get_instance_value(oid_memory_buffer, memory_data, "int")
		
	oid_memory_cached = "1.3.6.1.4.1.2021.4.15.0"
	memory_cached = get_instance_value(oid_memory_cached, memory_data, "int")
		
	memory_used = int(round(((memory_total - memory_avail - memory_buffer - memory_cached) / float(memory_total)) * 100))
	counter_name = "% Used Memory"
	snmp_data.append(build_counter_list(hostname, object_name, counter_name, instance_name, memory_used, counter_type))
		


#Getting Network OID Information
def get_network_counters():
	object_name = "Network"
	counter_type = "Perf"
	network_oid = "1.3.6.1.2.1.31.1.1.1"
	snmpwalk_flags = "n"
	network_data = get_snmp_data(host_address, network_oid, snmpwalk_flags)
	
	#First confirm which instance matches the networks to be reviewed, gathering ID and Name for each
	network_instances = []
	for network in network_data:
		if re.search("eth", network) or re.search("bond", network):
			network_instances.append(get_snmp_instances(network))
	
	#iterate through each network instance and get details of interestered OID
	for instance in network_instances:
	
		#Getting Network Rx stat
		oid_netrx = "1.3.6.1.2.1.31.1.1.1.6." + instance["id"]
		net_rx = get_instance_value(oid_netrx, network_data, "int")
		counter_name = "Total Bytes Received"
		snmp_data.append(build_counter_list(hostname, object_name, counter_name, instance["name"], net_rx, counter_type))
	
		oid_nettx = "1.3.6.1.2.1.31.1.1.1.10." + instance["id"]
		net_tx = get_instance_value(oid_nettx, network_data, "int")
		counter_name = "Total Bytes Transmitted"
		snmp_data.append(build_counter_list(hostname, object_name, counter_name, instance["name"], net_tx, counter_type))



#Getting Volume Information
def get_volume_counters():
	object_name = "Logical Volume"
	counter_type = "Status"
	volume_oid = "1.3.6.1.2.1.25.2.3.1"
	snmpwalk_flags = "n"
	volume_data = get_snmp_data(host_address, volume_oid, snmpwalk_flags)
	
	volume_instances = []
	for volume in volume_data:
		if re.search("/volume+[0-9]$", str(volume)):
			volume_instances.append(get_snmp_instances(volume))
			
	for instance in volume_instances:
		
		oid_volume_blocksize = "1.3.6.1.2.1.25.2.3.1.4." + instance["id"]
		volume_blocksize = get_instance_value(oid_volume_blocksize, volume_data, "int")
	
		oid_volume_size = "1.3.6.1.2.1.25.2.3.1.5." + instance["id"]
		volume_size = get_instance_value(oid_volume_size, volume_data, "int") * volume_blocksize
		counter_name = "Volume Size Bytes"
		snmp_data.append(build_counter_list(hostname, object_name, counter_name, instance["name"], volume_size, counter_type))
	    
		oid_volume_used = "1.3.6.1.2.1.25.2.3.1.6." + instance["id"]
		volume_used = get_instance_value(oid_volume_used, volume_data, "int") * volume_blocksize
		volume_used = int(math.ceil(round((volume_used / float(volume_size) ) * 100, 1)))
		counter_name = "% Used Space"
		snmp_data.append(build_counter_list(hostname, object_name, counter_name, instance["name"], volume_used, counter_type))



#Getting Disk Temperature Information
def get_disk_temperatures():
	object_name = "Physical Disk"
	counter_type = "Status"
	disk_oid = "1.3.6.1.4.1.6574.2.1.1"
	snmpwalk_flags = "n"
	disk_data = get_snmp_data(host_address, disk_oid, snmpwalk_flags)
	
	disk_instances = []
	for disk in disk_data:
		if re.search("Disk", disk) or re.search("Cache", disk):
			disk_instances.append(get_snmp_instances(disk))
	
	for instance in disk_instances:
		
		oid_disk_temp = "1.3.6.1.4.1.6574.2.1.1.6." + instance["id"]
		disk_temp = get_instance_value(oid_disk_temp, disk_data, "int")
		counter_name = "Disk Temperature"
		snmp_data.append(build_counter_list(hostname, object_name, counter_name, instance["name"], disk_temp, counter_type))


#Getting Logical Disk Information, still physical but MIB's separate the actual names and references so its focusing on more logical stats
def get_disk_counters():
	object_name = "Logical Disk"
	counter_type = "Perf"
	disk_oid = "1.3.6.1.4.1.6574.101.1.1"
	snmpwalk_flags = "n"
	disk_data = get_snmp_data(host_address, disk_oid, snmpwalk_flags)
	
	disk_instances = []
	for disk in disk_data:
		if re.search("sd", disk) or re.search("nvm", disk):
			disk_instances.append(get_snmp_instances(disk))
	
	for instance in disk_instances:
	
		oid_disk_reads = "1.3.6.1.4.1.6574.101.1.1.12." + instance["id"]
		disk_reads = get_instance_value(oid_disk_reads, disk_data, "int")
		counter_name = "Bytes Read Since Boot"
		snmp_data.append(build_counter_list(hostname, object_name, counter_name, instance["name"], disk_reads, counter_type))
		
		oid_disk_writes = "1.3.6.1.4.1.6574.101.1.1.13." + instance["id"]
		disk_writes = get_instance_value(oid_disk_writes, disk_data, "int")
		counter_name = "Bytes Written Since Boot"
		snmp_data.append(build_counter_list(hostname, object_name, counter_name, instance["name"], disk_writes, counter_type))
		
		oid_disk_load = "1.3.6.1.4.1.6574.101.1.1.8." + instance["id"]
		disk_load = get_instance_value(oid_disk_load, disk_data, "int")
		counter_name = "% Disk Load"
		snmp_data.append(build_counter_list(hostname, object_name, counter_name, instance["name"], disk_load, counter_type))


#Getting UPS Information
def get_ups_counters():
	
	global ups_name
    #Naming the instance of the UPS
	if ups_name == "":
		ups_name = hostname + "_UPS"

	object_name = "UPS"
	counter_type = "Status"
	ups_oid = "1.3.6.1.4.1.6574.4.3"
	snmpwalk_flags = "n"
	ups_data = get_snmp_data(host_address, ups_oid, snmpwalk_flags)
    
	oid_ups_runtime = "1.3.6.1.4.1.6574.4.3.6.1.0"
	ups_runtime = get_instance_value(oid_ups_runtime, ups_data, "int")
	counter_name = "Battery Runtime Seconds" 
	snmp_data.append(build_counter_list(hostname, object_name, counter_name, ups_name, ups_runtime, counter_type))
    
	oid_ups_charge = "1.3.6.1.4.1.6574.4.3.1.1.0"
	ups_charge = get_instance_value(oid_ups_charge, ups_data, "percent")
	counter_name = "% Battery Charge" 
	snmp_data.append(build_counter_list(hostname, object_name, counter_name, ups_name, ups_charge, counter_type))
    

    #ups_charge =  int(counter_value[0].split('.', 1)[0])

    

# Build the API signature
def build_signature(workspace_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash).encode('utf-8')  
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest())
    authorization = "SharedKey {}:{}".format(workspace_id,encoded_hash)
    return authorization

# Build and send a request to the POST API
def post_data(workspace_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(workspace_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + workspace_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print 'Accepted'
    else:
        print "Response code: {}".format(response.status_code)


#############################
######Gathering Metrics######
#############################

def __main__():
	
	#Empty list of all the metrics to be captured
	global snmp_data
	snmp_data = [] 
	
	#Getting Hostname (used for all metric host association) 
	global hostname
	if hostname == "":
		oid_hostname = "1.3.6.1.2.1.1.5"
		snmpwalk_flags = "qvt"
		counter_value = get_snmp_data(host_address, oid_hostname, snmpwalk_flags)
		hostname = counter_value[0]

	if capture_system_temperature == "true":
		get_system_temperature()
		
	if capture_cpu == "true":
		get_cpu_counters()
		
	if capture_memory == "true":
		get_memory_counters()
		
	if capture_network == "true":
		get_network_counters()
		
	if capture_volume == "true":
		get_volume_counters()
		
	if capture_disk == "true":
		get_disk_temperatures()
		get_disk_counters()
	
	
	if capture_ups == "true":
		get_ups_counters()
	
	#Convert list to JSON
	body = json.dumps(snmp_data)
	
	#Post data to Log Analytics Workspace
	post_data(workspace_id, shared_key, body, log_type)
	print(body)


__main__()
