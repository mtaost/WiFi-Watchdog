import string
import os 
import threading
import time
import logging
import pyshark
import netifaces
import re
import asyncio
from collections import OrderedDict 
from collections import defaultdict

import socket
import struct
import threading
import textwrap

import cherrypy
from cherrypy.process.plugins import SimplePlugin
import subprocess

#Returns a list of tuples of device name and MAC Address
def list_devices(interface):
	result = tuple()
	pattern = re.compile("(.*)\b?\((\d+\.\d+\.\d+\.\d+)\) at (\w\w\:\w\w\:\w\w\:\w\w\:\w\w\:\w\w) .* on " + interface)
	output = subprocess.check_output("arp -a", shell=True).decode().split('\n')
	for row in output:
		p = pattern.match(row)
		if p is not None:
			result = (p.groups(), ) + result
	return result

MIN_PACKET_SIZE = 200
mac_dict = OrderedDict();
wireless_macs = set()
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
pi_addr = netifaces.ifaddresses('wlan0')[netifaces.AF_LINK][0]['addr']
p = re.compile('(\d+\.\d+\.\d+)\.\d+')

class user_model:
	
	def __init__(self, name, dname):
		self.received = 0
		self.transmitted = 0
		self.name = name
		self.dname = dname
		self.web_weights = defaultdict(lambda: 0.0)
		
	def set_name(new_name):
		name = new_name

		

class StringGenerator(object):
    @cherrypy.expose
    def index(self):
        return """<!DOCTYPE HTML>
<!--
	Urban by TEMPLATED
	templated.co @templatedco
	Released for free under the Creative Commons Attribution 3.0 license (templated.co/license)
-->
<html>
	<head>
		<title>Wifi Watchdog</title>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<link rel="stylesheet" href="/static/css/main.css" />
	</head>
	<body>

		<!-- Header -->
			<header id="header" class="alt">
				
				<a href="#menu">Menu</a>
			</header>

		<!-- Nav -->
			<nav id="menu">
				<ul class="links">
					<li><a href="index.html">Home</a></li>
					<li><a href="/training/">Training</a></li>
					<li><a href="/monitor/">Monitor</a></li>
				</ul>
			</nav>

		<!-- Banner -->
			<section id="banner">
				<div class="inner">
					<header>
						<h1>Wifi Watchdog</h1>
						<p>Safeguard against malicious activity on your network by analyzing traffic patterns.</p>
					</header>
					
					<a href="/training/" class="button big scrolly">Training</a>   &nbsp; &nbsp; &nbsp;
					<a href="/monitor/" class="button big scrolly">Monitor</a>
					</br></br>
					<a href="/documentation/" class="button big scrolly" style="background-color:darkseagreen">Documentation</a>
				</div>
			</section>


		<!-- Scripts -->
			<script src="/static/js/jquery.min.js"></script>
			<script src="/static/js/jquery.scrolly.min.js"></script>
			<script src="/static/js/jquery.scrollex.min.js"></script>
			<script src="/static/js/skel.min.js"></script>
			<script src="/static/js/util.js"></script>
			<script src="/static/js/main.js"></script>

	</body>
</html>"""


class training(object):
	def generate_training():
		known_table = """<div class="table-wrapper">
											<table>
												<thead>
													<tr>
														<th>MAC Address</th>
														<th>Device Name</th>
														<th>Packets Received</th>
														<th>Packets Transmitted</th>
														<th>Owner</th>
													</tr>
												</thead>
												<tbody>
												
												"""
		unknown_table = """<div class="table-wrapper">
											<table>
												<thead>
													<tr>
														<th>MAC Address</th>
														<th>Device Name</th>
														<th>Packets Received</th>
														<th>Packets Transmitted</th>
														<th>Owner</th>
														<th>Action</th>
													</tr>
												</thead>
												<tbody>
												
												"""
		for key, value in mac_dict.items():
			if (value.name != 'pi'):
				if (value.name != 'unknown'):
					known_table += '<tr>'
					known_table += '<td>' + key + '</td>'
					known_table += '<td>' + value.dname + '</td>'
					known_table += '<td>' + str(value.received) + '</td>'
					known_table += '<td>' + str(value.transmitted) + '</td>'
					known_table += '<td>' + value.name + '</td>'
					known_table += '<tr>'
				else:
					unknown_table += '<tr>'
					unknown_table += '<td>' + key + '</td>'
					unknown_table += '<td>' + value.dname + '</td>'
					unknown_table += '<td>' + str(value.received) + '</td>'
					unknown_table += '<td>' + str(value.transmitted) + '</td>'
					unknown_table += '<td>' + value.name + '</td>'
					unknown_table += """<td> <form method="get" action="identify"> <input type="submit" value="Identify"/></form>"""
					unknown_table += '<tr>'
		known_table += """									</tbody>
											</table>
											</div>"""
			
		unknown_table += """									</tbody>
											</table>
											</div>"""
		return """<!DOCTYPE HTML>
	<!--
	Urban by TEMPLATED
	templated.co @templatedco
	Released for free under the Creative Commons Attribution 3.0 license (templated.co/license)
	-->
	<html>
	<head>
		<title>Wifi Watchdog</title>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<meta http-equiv="refresh" content="5">
		
		<link rel="stylesheet" href="/static/css/main.css" />
	</head>
	<body>

		<!-- Header -->
			<header id="header">

				<a href="#menu">Menu</a>
			</header>

		<!-- Nav -->
			<nav id="menu">
				<ul class="links">
					<li><a href="index.html">Home</a></li>
					<li><a href="/training/">Training</a></li>
					<li><a href="/monitor/">Monitor</a></li>
				</ul>
			</nav>

		
		<!-- Main -->
			<div id="main">
				<section class="wrapper style1">
					<div class="inner">

						<header class="align-center">
							<h1>Training</h1>
						</header>

						<!-- Content -->
							<h2 id="content">Known nodes</h2>
							""" + known_table + """

						<hr class="major" />
						
						<!-- Content -->
							<h2 id="content">Unknown nodes</h2>
							""" + unknown_table + """

						<hr class="major" />

						</div>
			</section>
		</div>

		<!-- Scripts -->
			<script src="/static/js/jquery.min.js"></script>
			<script src="/static/js/jquery.scrolly.min.js"></script>
			<script src="/static/js/jquery.scrollex.min.js"></script>
			<script src="/static/js/skel.min.js"></script>
			<script src="/static/js/util.js"></script>
			<script src="/static/js/main.js"></script>

	</body>
</html>"""

	@cherrypy.expose
	def index(self):
		
		a = training.generate_training()
		return a
		
	@cherrypy.expose
	def input_name(self, name):
		for key, value in mac_dict.items():
			if (value.name != 'pi' and value.name == 'unknown'):
				value.name = name
				break
		
		raise  cherrypy.HTTPRedirect("index")
		return training.generate_training()
	@cherrypy.expose
	def identify(self):
		new_user = None
		for key, value in mac_dict.items():
			if (value.name != 'pi' and value.name == 'unknown'):
				new_user = value
				break
		known_table = """<div class="table-wrapper">
											<table>
												<thead>
													<tr>
														<th>MAC Address</th>
														<th>Device Name</th>
														<th>Packets Received</th>
														<th>Packets Transmitted</th>
														<th>Owner</th>
													</tr>
												</thead>
												<tbody>
												
												"""
		unknown_table = """<div class="table-wrapper">
											<table>
												<thead>
													<tr>
														<th>MAC Address</th>
														<th>Device Name</th>
														<th>Packets Received</th>
														<th>Packets Transmitted</th>
														<th>Owner</th>
														<th>Action</th>
													</tr>
												</thead>
												<tbody>
												
												"""
		for key, value in mac_dict.items():
			if (value.name != 'pi'):
				if (value.name != 'unknown'):
					known_table += '<tr>'
					known_table += '<td>' + key + '</td>'
					known_table += '<td>' + value.dname + '</td>'
					known_table += '<td>' + str(value.received) + '</td>'
					known_table += '<td>' + str(value.transmitted) + '</td>'
					known_table += '<td>' + value.name + '</td>'
					known_table += '<tr>'
				else:
					unknown_table += '<tr>'
					unknown_table += '<td>' + key + '</td>'
					unknown_table += '<td>' + value.dname + '</td>'
					unknown_table += '<td>' + str(value.received) + '</td>'
					unknown_table += '<td>' + str(value.transmitted) + '</td>'
					unknown_table += '<td>' + value.name + '</td>'
					unknown_table += """<td> <form method="get" action="identify"> <input type="submit" value="Identify"/></form>"""
					unknown_table += '<tr>'
		known_table += """									</tbody>
											</table>
											</div>"""
			
		unknown_table += """									</tbody>
											</table>
											</div>"""
											
		choices = """
										<div class="box">
											Match probabilities: </br>
											"""

		for key, value in mac_dict.items():
			if (value.name != 'pi' and value.name != 'unknown'):
				a_dot_b = 0.0
				magnitude_b = 0.0
				for ip, a_count in new_user.web_weights.items():
					a_dot_b += (a_count * value.web_weights[ip])
				for ip, b_count in value.web_weights.items():
					magnitude_b += (b_count * b_count)
				print(a_dot_b, " and ", magnitude_b)
				print ("new user has ", (a_dot_b/magnitude_b*100.0), "% match with ", value.name, "'s ", value.dname)
				choices+= "&#9;" + str(a_dot_b/magnitude_b*100.0) + "% match with " + value.name + "'s " + value.dname + "</br>"
		choices += """</br></pre>Real User Name: <form action="input_name" method="GET">
				  <input type="text" name="name"/>
				  <input type="submit" value="submit"/>
				</form></pre></div>"""
		return """<!DOCTYPE HTML>
	<!--
	Urban by TEMPLATED
	templated.co @templatedco
	Released for free under the Creative Commons Attribution 3.0 license (templated.co/license)
	-->
	<html>
	<head>
		<title>Wifi Watchdog</title>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<meta http-equiv="refresh" content="5"/>
		
		<link rel="stylesheet" href="/static/css/main.css" />
	</head>
	<body>

		<!-- Header -->
			<header id="header">

				<a href="#menu">Menu</a>
			</header>

		<!-- Nav -->
			<nav id="menu">
				<ul class="links">
					<li><a href="index.html">Home</a></li>
					<li><a href="/training/">Training</a></li>
					<li><a href="/monitor/">Monitor</a></li>
				</ul>
			</nav>

		
		<!-- Main -->
			<div id="main">
				<section class="wrapper style1">
					<div class="inner">

						<header class="align-center">
							<h1>Training</h1>
						
						</header>

						<!-- Content -->
							<h2 id="content">Known nodes</h2>
							""" + known_table + """

						<hr class="major" />
						
						<!-- Content -->
							<h2 id="content">Unknown nodes</h2>
							""" + unknown_table + """

						<hr class="major" />

						</div> """ + choices + """
			</section>
		</div>

		<!-- Scripts -->
			<script src="/static/js/jquery.min.js"></script>
			<script src="/static/js/jquery.scrolly.min.js"></script>
			<script src="/static/js/jquery.scrollex.min.js"></script>
			<script src="/static/js/skel.min.js"></script>
			<script src="/static/js/util.js"></script>
			<script src="/static/js/main.js"></script>

	</body>
</html>"""
	
class monitor(object):
	@cherrypy.expose
	def index(self):
		return '404'

class ExamplePlugin(SimplePlugin):

	_thread   = None
	_running  = None

	_sleep = None
	_paused = None
	

	def __init__(self, bus, sleep = 2):
		SimplePlugin.__init__(self, bus)
		self._paused = False
		self._sleep = sleep
		self.count = 0
		mac_dict[pi_addr] = user_model('pi', '')
		conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
		for tuple in list_devices('wlan0'):
			if (tuple[2].upper() not in wireless_macs):
				print(tuple[2].upper())
				wireless_macs.add(tuple[2].upper())
				mac_dict[tuple[2].upper()] = user_model('unknown', tuple[0])

	def start(self):
		
		# You can listen for a message published in request handler or
		# elsewhere. Usually it's putting some into the queue and waiting 
		# for queue entry in the thread.
		
		
		self._running = True
		if not self._thread:
			self._thread = threading.Thread(target = self._target)
			self._thread.start()
		
  # Make sure plugin priority matches your design e.g. when starting a
  # thread and using Daemonizer which forks and has priority of 65, you
  # need to start after the fork as default priority is 50
  # see https://groups.google.com/forum/#!topic/cherrypy-users/1fmDXaeCrsA
	start.priority = 70 

	def stop(self):
		print('stop')
		self.bus.log('Freeing up example plugin')
		self._running = False

		if self._thread:
			self._thread.join()
			self._thread = None

	def exit(self):
		self.unsubscribe()

	def _target(self):
		while self._running:
			try:
				if (self.count % 100 == 9):
					for tuple in list_devices('wlan0'):
						if (tuple[2].upper() not in wireless_macs):
							print(tuple[2].upper())
							wireless_macs.add(tuple[2].upper())
							mac_dict[tuple[2].upper()] = user_model('unknown', tuple[0])
				self.count += 1
				raw_data, addr = conn.recvfrom(65536)
				dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
				#print(dest_mac, "   ", eth_proto, "   ", len(data))
				
				if eth_proto == 8:
					(version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data)

					if (len(data) > MIN_PACKET_SIZE and dest_mac in wireless_macs and dest_mac != pi_addr):
						ip = p.match(src).group(1)
						mac_dict[dest_mac].web_weights[ip] += 1
						mac_dict[dest_mac].received += 1
					if (len(data) > MIN_PACKET_SIZE and src_mac in wireless_macs and src_mac != pi_addr):
						ip = p.match(target).group(1)
						mac_dict[src_mac].web_weights[ip] += 1
						mac_dict[src_mac].transmitted += 1
			except:
				self.bus.log('Error in example plugin', level = logging.ERROR, traceback = True)


def _redo(self, arg):
	time.sleep(self._sleep)
	raise cherrypy.HTTPRedirect("")
	self.bus.log('handling the message: {0}'.format(arg))


# Unpack Ethernet Frame
def ethernet_frame(data):
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

    # Format MAC Address
def get_mac_addr(bytes_addr):
	bytes_str = map('{:02x}'.format, bytes_addr)
	mac_addr = ':'.join(bytes_str).upper()
	return mac_addr

# Unpack IPv4 Packets Recieved
def ipv4_Packet(data):	
	version_header_len = data[0]
	version = version_header_len >> 4
	header_len = (version_header_len & 15) * 4
	ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

# Returns Formatted IP Address
def ipv4(addr):
	return '.'.join(map(str, addr))


# Unpacks for any ICMP Packet
def icmp_packet(data):
	icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
	return icmp_type, code, checksum, data[4:]

# Unpacks for any TCP Packet
def tcp_seg(data):
	(src_port, destination_port, sequence, acknowledgenment, offset_reserv_flag) = struct.unpack('! H H L L H', data[:14])
	offset = (offset_reserv_flag >> 12) * 4
	flag_urg = (offset_reserved_flag & 32) >> 5
	flag_ack = (offset_reserved_flag & 32) >>4
	flag_psh = (offset_reserved_flag & 32) >> 3
	flag_rst = (offset_reserved_flag & 32) >> 2
	flag_syn = (offset_reserved_flag & 32) >> 1
	flag_fin = (offset_reserved_flag & 32) >> 1

	return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Unpacks for any UDP Packet
def udp_seg(data):
	src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
	return src_port, dest_port, size, data[8:]	

if __name__ == '__main__':
	conf = {
		'/': {
			'tools.sessions.on': True,
			'tools.staticdir.root': os.path.abspath(os.getcwd())
		},
		'/static': {
			'tools.staticdir.on': True,
			'tools.staticdir.dir': './public'
		},
		'global' : {
    'server.socket_host' : '127.0.0.1',
    'server.socket_port' : 8080,
    'server.thread_pool' : 8
  }
	}
	mac_dict[pi_addr] = user_model('pi', '')
	
	ExamplePlugin(cherrypy.engine).subscribe()
	root = StringGenerator();
	root.training = training();
	root.monitor = monitor();
	cherrypy.quickstart(root, '/', conf)
	

