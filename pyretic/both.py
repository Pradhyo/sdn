from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from mac_learner import *
from simple_fw import *
from monitor import *

def main ():
    #return packet_counts() + firewall() >> mac_learner()   #All traffic
	return firewall() >> mac_learner() >> packet_counts()  #Only through firewall
