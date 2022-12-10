"""
Three devices on same network and all connected by a switch

	host --- switch ---- host

		   |
		   |
		   |
		   host

"""

from mininet.topo import Topo

class MyTopo(Topo):
    "Simple topology example."

    def __init__(self):
	"Create custom topology."

	#Initialize the topology
	Topo.__init__(self)
	
	"""
	[555 Comments]
	Your topology file for scenario 1. Define all the required devices here.
	"""
	Host1 = self.addHost('h1',ip = "10.0.0.2/24",defaultRoute = "via 10.0.0.1")
	Host2 = self.addHost('h2',ip = "10.0.0.3/24",defaultRoute = "via 10.0.0.1")
	Host3 = self.addHost('h3',ip = "10.0.0.4/24",defaultRoute = "via 10.0.0.1")
	switch = self.addSwitch('s1')

	self.addLink(Host1,switch)
	self.addLink(Host2,switch)
	self.addLink(Host3,switch)

topos = { 'mytopo':(lambda:MyTopo())}
