import subprocess
import re

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

list_devices('wlan0')