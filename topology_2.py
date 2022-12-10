"""
Three devices on different networks and all connected by a single router

	host --- router ---- host
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
	Your topology file for scenario 2. Define all the required devices here.
	"""
	Host1 = self.addHost('h1',ip = "10.0.0.2/24",defaultRoute = "via 10.0.0.1")
	Host2 = self.addHost('h2',ip = "20.0.0.2/24",defaultRoute = "via 20.0.0.1")
	Host3 = self.addHost('h3',ip = "30.0.0.2/24",defaultRoute = "via 30.0.0.1")
	router= self.addSwitch('r1')
	self.addLink(Host1,router)
	self.addLink(Host2,router)
	self.addLink(Host3,router)
topos = { 'mytopo':(lambda:MyTopo())}
