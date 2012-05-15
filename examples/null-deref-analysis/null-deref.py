#!/usr/bin/env python
##
## Copyright (c) 2011, 2012 The University of Utah
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License as
## published by the Free Software Foundation; either version 2 of
## the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.

###############################################################################
# 

import sys
import subprocess
import shlex
import time
import signal

SUDO = '/usr/bin/sudo'
KILLALL = '/usr/bin/killall'
XM = '/usr/sbin/xm'
TTD_DAEMON = '/usr/sbin/ttd-deviced'

DOMAIN_NAME = 'clientA'
DOMAIN_CONFIG = '/local/sda4/vm-images/client_A_solo_with_net.conf'
DOMAIN_SYSMAP = '/boot/System.map-2.6.18-xenU'
TTD_LOG = '/local/sda4/logs/ttd.log'

TTD_OUT = './ttd-deviced.run'
DOMAIN_OUT = './' + DOMAIN_NAME + '.run'

def run_ttd_daemon(sudo, ttd_daemon, ttd_log, out):
	run = open(out, 'w')
	cmd = sudo + ' ' + ttd_daemon  + ' -f ' + ttd_log
	p = subprocess.Popen(cmd, shell=True, stdout=run, stderr=run)
	return p

def run_replay_session(sudo, xm, domain_config, pause):
	cmd = sudo + ' ' + xm + ' create ' + domain_config + \
		' time_travel=\'ttd_flag=1, tt_replay_flag=1\''
	if pause == True:
		cmd += ' -p'
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
	return p

def log_replay_session(sudo, xm, domain_name, out):
	run = open(out, 'w')
	cmd = sudo + ' ' + xm + ' console ' + domain_name
	p = subprocess.Popen(cmd, shell=True, stdout=run)
	return p

def kill_replay_session(sudo, xm, domain_name):
	cmd = sudo + ' ' + xm + ' destroy ' + domain_name
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	return p

def killall(sudo, killall, comm):
	cmd = sudo + ' ' + killall + ' -9 ' + comm
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	return p

def tail(path):
	tmp = path.split('/')
	return tmp[-1]

def kill_everything():
	p = kill_replay_session(SUDO, XM, DOMAIN_NAME)
	p.wait()
	p = killall(SUDO, KILLALL, tail(TTD_DAEMON))
	p.wait()

def signal_handler(signal, frame):
	print 'You pressed Ctrl+C!'
	kill_everything()
	sys.exit(0)

if __name__ == '__main__':
	kill_everything()
	
	signal.signal(signal.SIGINT, signal_handler)
	
	print 'Starting Time Travel daemon...'
	run_ttd_daemon(SUDO, TTD_DAEMON, TTD_LOG, TTD_OUT)
	time.sleep(1)
	print 'Time Travel daemon started'

	print 'Starting replay session...'
	p = run_replay_session(SUDO, XM, DOMAIN_CONFIG, True)
	exitcode = p.wait()
	if exitcode != 0:
		print "Failed to start replay session!"
		p = kill_replay_session(SUDO, XM, DOMAIN_NAME)
		p.wait()
		sys.exit(exitcode)
	print 'Replay session started and paused.'
	
	print 'Logging replay session to ' + DOMAIN_OUT
	p = log_replay_session(SUDO, XM, DOMAIN_NAME, DOMAIN_OUT)
	p.wait()

	kill_everything()
	sys.exit(0)
