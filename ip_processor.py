#!/usr/bin/env python

import os, sys, subprocess, re, datetime, copy
import urllib, json
import time
from logging import Logger
from collections import defaultdict, Counter

ipFile = open(sys.argv[1])
#print ipFile

#log = Logger()
ips_by_date = defaultdict(Counter)
name = dict()
loc = dict()
geoloc = dict()

BOLD = '\033[1m'
END = '\033[0m'

if not os.path.isdir("whoisCache"):
	os.mkdir("whoisCache")
if not os.path.isdir("geoipCache"):
	os.mkdir("geoipCache")
if not os.path.isdir("visitHistograms"):
	os.mkdir("visitHistograms")

# get start analysis time from token file
token_filename = "whoisCache/token"
start_analysis = None
if os.path.isfile(token_filename):
	start_analysis = open(token_filename).read().strip()
else:
	start_analysis = "01/01/2015"

start_analysis_time = datetime.datetime.strptime(start_analysis, "%m/%d/%Y")
latest_time = copy.copy(start_analysis_time)

# check to see if blacklist exists; if so, use
# blacklist is a line break-separated list of IPs you don't want to see in 
# your visit histograms 
use_blacklist = True
blacklist = []
if os.path.isfile("blacklist") and use_blacklist:
	blacklist = set(open("blacklist").read().splitlines())

# check to see if whitelist exists; if so, use
# whitelist is a line break-separated list of IPs you definitely want to see
# in your visit histograms 
# will also bold whitelist! will bold no matter what
# if you'd like to see ONLY whitelisted in your output, set use_whitelist to
# True
use_whitelist = False
whitelist = []
if os.path.isfile("whitelist"):
	whitelist = set(open("whitelist").read().splitlines())

def getWhoisForIP(ip):
	whois_result_file = "whoisCache/%s.txt" % ip
	whois_result = None
	if os.path.isfile(whois_result_file):
		whois_file = open(whois_result_file)
		whois_result = whois_file.read()
		return whois_result
	
	whois_result = subprocess.check_output("whois %s" % ip, shell=True)	
	whois_file = open(whois_result_file, "w")
	whois_file.write(whois_result)
	whois_file.flush()
	whois_file.close()

	return whois_result

def getGeoIPLookup(ip):
    geoip_result_file = "geoipCache/%s.txt" % ip
    geoip_result = None
    if os.path.isfile(geoip_result_file):
            geoip_file = open(geoip_result_file)
            geoip_result = geoip_file.read()
            print "READ:"
            print geoip_result
            return json.loads(geoip_result)
	
    obtained = False
    while not obtained:
        geoip_result = urllib.urlopen("http://freegeoip.net/json/%s" % ip).read()
        print "OBTAINED:"
        print geoip_result
        if re.match("Try again later", geoip_result):
           obtained = False
           time.sleep(5)
        else:
           obtained = True

        
    geoip_dict = json.loads(geoip_result)
    geoip_file = open(geoip_result_file, "w")
    geoip_file.write(geoip_result)
    geoip_file.flush()
    geoip_file.close()

    return geoip_dict

def printIPVisitHistogram(ips,date_str,out):
	#log.debug ("# Printing IP visit histogram")
	out.write("%s:\n%s\n" % (date_str, "-"*80))
	for ip in sorted(ips, key=lambda x: -1*ips[x]):
		#log.debug("ip lookup: %s" % ip)
		#log.debug("ips[ip]: %s" % str(ips[ip]))
		#log.debug("ips[ip]: %s" % str(ips[ip]))
		if use_blacklist and ip in blacklist:
			continue
		if use_whitelist and ip not in whitelist:
			continue
		end_seq = "\n"
		if ip in whitelist:
			out.write(BOLD)
			end_seq = "%s\n" % (END)
		out.write((ips[ip]*"=").rjust(20) +
                        (" %s " % ip.rjust(15)) +
                        (" %s " % (geoloc[ip].rjust(18)) +
                            (" %s " % loc[ip].ljust(25)) + name[ip] + end_seq))


for line in ipFile.readlines():
	line_arr = line.split(" ")
	date = line_arr[0].strip()
	parse_time = line_arr[1].strip()
	page = line_arr[2].strip()
	ip = line_arr[3]
	ip = ip.strip()
	link_from = None
	if len(line_arr) > 4:
		link_from = line_arr[4].strip()

	# check if we should process this date or if it's been
	# processed before
	date_time = datetime.datetime.strptime(date, "%m/%d/%Y")
	if not (date_time >= start_analysis_time):
		continue
	ips = ips_by_date[date_time]
	ips[ip] += 1

	# update latest_time if this is a new date, to go in
	# token file later
	if date_time > latest_time:
		latest_time = copy.copy(date_time)

	# process whois result
	ip_filename = "whoisCache/%s.txt" % ip
	whois_arr = getWhoisForIP(ip).splitlines()

	org_name = ""
	for whois_line in whois_arr:
		m = re.match("OrgName: (.*)",whois_line)
		if m is not None:
			org_name = str(m.groups(1)[0].strip())
			name[ip] = org_name
			break


	descr = ""
	if not org_name:
		for whois_line in whois_arr:
			m = re.match("descr: (.*)",whois_line)
			if m is not None:
				descr = str(m.groups(1)[0].strip())
				name[ip] = descr
				break

		# if none has been found
		if not descr:
			name[ip] = "???"

	location = ""
        loc_dict = getGeoIPLookup(ip)
        location = "%s, %s, %s" % (loc_dict["city"],
                                   loc_dict["region_code"],
                                   loc_dict["country_code"])
        loc[ip] = location

        lat_long = "%s, %s" % (loc_dict["latitude"],
                               loc_dict["longitude"])
        geoloc[ip] = lat_long
#	city = ""
#	stateprov = ""
#	country = ""
#	for whois_line in whois_arr:
#		m = re.match("City: (.*)",whois_line)
#		if m is not None:
#			city = str(m.groups(1)[0].strip())
#		m = re.match("StateProv: (.*)",whois_line)
#		if m is not None:
#			stateprov = str(m.groups(1)[0].strip())		
#		m = re.match("Country: (.*)",whois_line)
#		if m is not None:
#			country = str(m.groups(1)[0].strip())		
#
#	if city is not "" or stateprov is not "" or country is not "":
#		location = "%s, %s, %s" % (city, stateprov, country)
#		loc[ip] = location
#	else:
#		loc[ip] = ""

	# output details for visits since start_analysis_time
	sys.stdout.write( "Date: %s\n" % date)
	sys.stdout.write( "Time: %s\n" % parse_time)
	sys.stdout.write( "Page: %s\n" % page)
	sys.stdout.write( "IP: %s\n" % ip)
	if org_name:
		sys.stdout.write( "Org Name: %s\n" % org_name)
	elif descr:
		sys.stdout.write( "Description: %s\n" % descr)
	elif location:
		sys.stdout.write( "Location: %s\n" % location)
		sys.stdout.write( "Lat / Long: %s\n" % lat_long)
	else:
		sys.stdout.write( "From ??? Check WHOIS output! %s\n" % ip_filename)
	sys.stdout.write( "Referrer: %s\n" % link_from)
	sys.stdout.flush()

for date_time in sorted(ips_by_date):
	date_str = date_time.strftime("%Y-%m-%d") 
	date_result_file = "visitHistograms/visits-%s.txt" % date_str

	result_file = open(date_result_file, "w")
	printIPVisitHistogram(ips_by_date[date_time], date_time.strftime("%m/%d/%Y"), result_file)
	result_file.close()
	sys.stderr.write("Output results for %s to %s.\n" % (date_str, date_result_file))

# put latest_time into token_file
token_file = open(token_filename, "w")
token_file.write(latest_time.strftime("%m/%d/%Y\n"))
token_file.flush()
token_file.close()
