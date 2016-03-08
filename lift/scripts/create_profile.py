import argparse,sys,time,json

def get_input():
	filename = raw_input("Name of file: ")
	company_name = raw_input("Company Name: ")
	website_name = raw_input("Website Name: ")
	brief_description = raw_input("Brief Description: ")
	create_template(filename,company_name,website_name,brief_description)

def create_template(fname,compname,webname,brdesc):
	filepath = '/opt/sectools/lift/lib/profiles/' + fname
	f = open(filepath,'w+')
	attributes = {'company_name':compname, 'website':webname, 'description': brdesc}
	j = json.dumps(attributes)
	f.write(j)
	f.close()

get_input()
