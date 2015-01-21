from pox.lib.addresses import EthAddr

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from mac_learner import *

class firewall(DynamicPolicy):

    def __init__(self):
        # Initialize the firewall
        print "initializing firewall"      
        self.firewall = {}
        super(firewall,self).__init__(true)
        mac1 = MAC("00-00-00-00-00-02")
        mac2 = MAC("00-00-00-00-00-03")
        self.firewall[(mac1,mac2)]=True
        print "Adding firewall rule in %s: %s" % (mac1,mac2) 
        self.policy = ~union([ (match(srcmac=mac1) & 
                                match(dstmac=mac2)) |
                               (match(dstmac=mac1) & 
                                match(srcmac=mac2)) 
                               for (mac1,mac2) 
                               in self.firewall.keys()])


def main ():
    return firewall() >> mac_learner()
