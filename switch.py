"""
[555 Comments]
Your switch code and any other helper functions related to switch should be written in this file
"""
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import *
from pox.lib.addresses import *
from pox.lib.packet.icmp import *
from pox.lib.packet.ipv4 import *

log = core.getLogger()

"""
[555 Comments]
  Function : switch_handler
  Input Parameters:
      sw_object : The switch object. This will be initialized in the controller file corresponding to the scenario in __init__
                  function of tutorial class. Any data structures you would like to use for a switch should be initialized
                  in the contoller file corresponding to the scenario.
      packet    : The packet that is received from the packet forwarding switch.
      packet_in : The packet_in object that is received from the packet forwarding switch
"""
def switch_handler(sw_object, packet, packet_in):
	#print("This is the packetin")
	#print(packet_in)
	#print("This is the packet")
	#print(packet)
	sourceport = packet_in.in_port
	sourcemac = str(packet.src)
	destinmac = str(packet.dst)
	print("========================================")
	print("A packet from",sourcemac,"try going to",destinmac,"via",sourceport)
	sw_object.mac_to_port[sourcemac] = sourceport
	protocol = packet.payload
  	print(protocol)
		
	if destinmac in sw_object.mac_to_port:
		#first send the package
		destinport = sw_object.mac_to_port[destinmac]
		sw_object.resend_packet(packet_in,destinport)
		#install rules for switch
		msg = of.ofp_flow_mod()
		msg.match.in_port = sourceport
		msg.match.dl_dst = packet.dst
		msg.actions.append(of.ofp_action_output(port = destinport))
		sw_object.connection.send(msg)
	else:  
		#no record just flood
		sw_object.resend_packet(packet_in, of.OFPP_ALL)
