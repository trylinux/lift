import paramiko, base64,sys,time,signal,os
import argparse
def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i","--ifile", help="A list of IPs")
	parser.add_argument("-o","--ofile", help="A file you can append to")
	parser.add_argument("-p","--password",help="The password you want to attempt to use")
	parser.add_argument("-u","--user", help="The user you want to use")
	args=parser.parse_args()
	IP_file = args.ifile
	success_file = args.ofile
	user = args.user
	password = args.password
	fb = open(success_file,'a')
	with open(IP_file) as f:
		for line in f:
			client = paramiko.SSHClient()
			client.set_missing_host_key_policy(paramiko.AutoAddPolicy())	
			try:
				if client.connect(str(line), username=str(user), password=str(password), timeout=5) is None:
					print "Success " +str(line)
					fb.write(str(line))
					client.close()
			except KeyboardInterrupt:
					client.close()
					print "Quitting "
					sys.exit(0)
			except:
					pass
					print "Failure for " + line
					client.close()
	fb.close()
if __name__ == '__main__':
	main()
