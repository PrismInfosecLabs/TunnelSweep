#!/usr/bin/python3
import pexpect,time,os,threading
# Author: Alexis Vanden Eijnde
# Date: 16/02/2021
#
# Iterate through remote hosts and ports to see if anything is listening on the server
# useful for when no shell access is provided
#
# Bugs and notes:
# can't seem to catch the timeout exception properly with pexpect, causes some false positives
# slow as needs to set up the ssh, and then query the port with nc locally
# should be improved by multi-threading, i.e bind 5-10 services at a time, instead of one
# to reduce the FP's, re-run the scan again on the ports it thinks are open.

local_bind_port = 31337
ssh_pass = 'password'
ssh_port = 443
username = 'username'
server = 'victim.com'
internal_ip_list = ["127.0.0.1","10.10.10.10"]
common_ports = [ 21, 22, 80, 443, 8080, 8834, 3389, 3306]
#wait for ssh to set up before poking
poke_delay = 1
#first manually test how long the timeout before a message about invalid port comes back before setting this
pexpect_timeout = 5
#first manually test what error message comes back for an invalid port, as different SSH version differ in response:
invalid_regex=".*connect failed"
potential_valid_ports = []

def ssh(remote_port,internal_ip):
	try:
		ssh_cmd = 'ssh -CnfN -L %s:%s:%s -p %s %s@%s' % (local_bind_port,internal_ip,remote_port,ssh_port,username,server)
		child = pexpect.spawn(ssh_cmd)
		child.expect(['[pP]assword: '])
		child.sendline(ssh_pass)
		child.expect(invalid_regex,timeout=pexpect_timeout)
		print('\x1b[1;31m[-] Connection refused string, nothing listening on '+internal_ip+':'+str(remote_port)+'\x1b[0m')
		kill_tunnel()
	# timeout seems to throw EOF exception, so use this ¯\_(ツ)_/¯
	# generates some false positives but better then nothing for a quick script
	# TODO: need to actually capture pexpect.TIMEOUT and not EOF exception
	except pexpect.exceptions.EOF as e:
		print('\x1b[1;32m[+] Exception Occurred, potential valid port --[ '+internal_ip+':'+str(remote_port)+' ]--\x1b[0m')
		potential_valid_ports.append((internal_ip,remote_port))
		kill_tunnel()

# can't close properly due to background_process - bit of a hack:
# sometimes the process isn't there and throws an error - all output to dev null to look nicer
def kill_tunnel():
	kill_cmd = 'kill -9 $(lsof -t -i:%s ) > /dev/null 2>&1' % local_bind_port
	os.system(kill_cmd)

# send a connection to the localhost listening
# if nothing exists, usually get a 'connect failed' (SSH version dependent) from ssh
# use this to identify that nothing is listening on the remote port
def poke():
	prod_cmd = 'nc 127.0.0.1 %s  > /dev/null 2>&1' % local_bind_port
	time.sleep(poke_delay)
	os.system(prod_cmd)


if __name__ == "__main__":
	for ip in internal_ip_list:
		for port in common_ports:
			tunnel = threading.Thread(target=ssh, args=(port,ip))
			killer = threading.Thread(target=poke)
			tunnel.start()
			killer.start()
			# wait for process to die before going onto next port
			tunnel.join()
			killer.join()
print('\n\x1b[1;32m------------------------[SCAN FINISED]------------------------\n')
print('Manually try the following ports, or run the script again with the following IP\'s and ports to reduce the FP\'s:\n')
print(str(potential_valid_ports))
