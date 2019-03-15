import pyshark
cap = pyshark.LiveCapture(interface='wlan0')
cap.sniff(timeout=5)
for packet in cap:
	if (int(packet.length) > MIN_PACKET_SIZE):
		if (packet.layers[0]._all_fields.get('eth.src') != pi_addr):
			new_addr = packet.layers[0]._all_fields.get('eth.src')
			if (new_addr not in mac_dict):
				mac_dict[new_addr] = user_model("unknown")
			ip = packet.layers[1]._all_fields.get('ip.dst')
			ip = p.match(ip).group(1)
			mac_dict[new_addr].web_weights[ip] += 1
			mac_dict[new_addr].transmitted += 1
		if (packet.layers[0]._all_fields.get('eth.dst') != pi_addr):
			new_addr = packet.layers[0]._all_fields.get('eth.dst')
			if (new_addr not in mac_dict):
				mac_dict[new_addr] = user_model("unknown")
			ip = packet.layers[1]._all_fields.get('ip.dst')
			ip = p.match(ip).group(1)
			mac_dict[new_addr].received += 1
			mac_dict[new_addr].web_weights[ip] += 1