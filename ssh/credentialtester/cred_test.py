import paramiko,sys,argparse,signal,time
def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i","--ifile", help="A list of IPs")
	parser.add_argument("-o","--ofile", help="A file you can append to. Will create if it does not exist")
	parser.add_argument("-p","--password",help="The password you want to attempt to use")
	parser.add_argument("-u","--user", help="The user you want to use")
	args=parser.parse_args()
	IP_file = args.ifile
	success_file = args.ofile
	user = args.user
	password = args.password
	paramiko.util.log_to_file("filename.log")
	fb = open(success_file,'a+')
	with open(IP_file) as f:
		for line in f:
			client = paramiko.SSHClient()
			client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			try:
				if client.connect(str(line), username=str(user), password=str(password), timeout=5) is None:
					transport = client.get_transport()
					channel = transport.open_session()
					start = time.time()
					while time.time() < start + 15:
						if channel.active == 1:
							fb.write(str(line))
							print "Success " +str(line)	
							client.close()
							channel.close()
							break
						else:
							print "Failure " +str(line)
							client.close()
							break
					client.close()
					
			except KeyboardInterrupt:
					client.close()
					print "Quitting "
					sys.exit(0)
			except signal.SIGSTOP:
					pass
					client.close()
			except:
					pass
					print "Failure for " + line
					client.close()
	fb.close()
if __name__ == '__main__':
	main()
