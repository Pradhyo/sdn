from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from mac_learner import *


def packet_count_printer(counts):
    if counts:
    	print counts 
    	print

def count1():
	q = (match(srcmac=EthAddr('00:00:00:00:00:01')) >> packet_counts()) + (match(dstmac=EthAddr('00:00:00:00:00:01')) >> packet_counts())
	return q

def packet_counts():
  q = count_packets(1,['srcip','dstip'])
  q.register_callback(packet_count_printer)
  return q

def main():
    return mac_learner() + count1()