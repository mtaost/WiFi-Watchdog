import pyshark
import netifaces
from collections import defaultdict

MIN_PACKET_SIZE = 200


#Takes in a device mac address, an interface, and a time to monitor it
def monitor_device(mac_addr, ifinterface, interval):
	cap = pyshark.LiveCapture(interface=ifinterface)
	cap.sniff(timeout = interval)
	#output dict is in format of IP1:packets, IP2:#packets
	output = defaultdict(lambda: 0)

	for packet in cap._packets:
		if (packet.layers[0]._all_fields.get('eth.src') == mac_addr and int(packet.length) > MIN_PACKET_SIZE):
			output[packet.layers[1]._all_fields.get('ip.dst')] = output[packet.layers[1]._all_fields.get('ip.dst')] + 1
		elif (packet.layers[0]._all_fields.get('eth.dst') == mac_addr and int(packet.length) > MIN_PACKET_SIZE):
			output[packet.layers[1]._all_fields.get('ip.src')] = output[packet.layers[1]._all_fields.get('ip.src')] + 1

	return output

exitFlag = 0

