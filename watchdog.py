import dev_monitor as dm 
import threading
import asyncio
import time
import pyshark
import netifaces
from collections import defaultdict

#import pandas as pd
import numpy as np
# from sklearn.model_selection import train_test_split
# from sklearn.ensemble import RandomForestClassifier
# import forestci as fci

MIN_PACKET_SIZE = 200

threads = []
ips = []
device_logs = {}
test = {'f8:32:e4:13:c5:e7':'Michael Zenpad', 'c0:ee:fb:f4:e4:48':'Michael OP3T', 'ac:37:43:4a:f1:1f' : 'Michael Pixel' }

#Takes in a device mac address, an interface, and a time to monitor it
def monitor_device(mac_addr, ifinterface, interval):
	cap = pyshark.LiveCapture(interface=ifinterface)
	cap.sniff(timeout = interval)
	#output dict is in format of IP1:packets, IP2:#packets
	output = defaultdict(lambda: 0)

	for packet in cap._packets:
		ip = []
		if (packet.layers[0]._all_fields.get('eth.src') == mac_addr and int(packet.length) > MIN_PACKET_SIZE):
			ip = packet.layers[1]._all_fields.get('ip.dst')
			output[ip] = output[ip] + 1

		elif (packet.layers[0]._all_fields.get('eth.dst') == mac_addr and int(packet.length) > MIN_PACKET_SIZE):
			ip = packet.layers[1]._all_fields.get('ip.src')
			output[packet.layers[1]._all_fields.get('ip.src')] = output[packet.layers[1]._all_fields.get('ip.src')] + 1

		if ip not in ips:
			ips.append(ip)
		# Append the row with User, mac addr, ip column
		device_logs[mac_addr] = output

#Devices is a list of mac_addr
def monitor_devices(devices, ifinterface, interval):
	for dev in devices:
		print("Gathering data for: " + dev)
		monitor_device(dev, ifinterface, interval)

	#Threading code that doesn't work
	# 	process = threading.Thread(target = monitor_device, args = [dev, ifinterface, interval])
	# 	print("Running thread " + dev)
	# 	process.start()
	# 	threads.append(process)

	# for process in threads:
	# 	process.join()

# user_devs is a dict of mac_addr:users
# interval is the individual sniffing interval for one row of data
# time is the total amount of time for which to scan over
def gather_data(user_devs, ifinterface, interval, count):
	for i in range(count):
		monitor_devices(user_devs.keys(), ifinterface, interval)

		#for device in device_logs:
			#ips.append(device_logs[device].keys())
			#df = pd.DataFrame


# from sklearn.ensemble import RandomForestClassifier
# from sklearn.datasets import make_classification
# X, y = make_classification(n_samples=1000, n_features=4,
#                             n_informative=2, n_redundant=0,
#                             random_state=0, shuffle=False)

# clf = RandomForestClassifier(n_estimators=100, max_depth=2,
#                              random_state=0)
# clf.fit(X, y)
# RandomForestClassifier(bootstrap=True, class_weight=None, criterion='gini',
#             max_depth=2, max_features='auto', max_leaf_nodes=None,
#             min_impurity_decrease=0.0, min_impurity_split=None,
#             min_samples_leaf=1, min_samples_split=2,
#             min_weight_fraction_leaf=0.0, n_estimators=100, n_jobs=None,
#             oob_score=False, random_state=0, verbose=0, warm_start=False)
# print(clf.feature_importances_)
# [0.14205973 0.76664038 0.0282433  0.06305659]
# print(clf.predict([[0, 0, 0, 0]]))
# [1]