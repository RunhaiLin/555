"""
[555 Comments]
Your router code and any other helper functions related to router should be written in this file
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
  Function : router_handler
  Input Parameters:
      rt_object : The router object. This will be initialized in the controller file corresponding to the scenario in __init__
                  function of tutorial class. Any data structures you would like to use for a router should be initialized
                  in the contoller file corresponding to the scenario.
      packet    : The packet that is received from the packet forwarding switch.
      packet_in : The packet_in object that is received from the packet forwarding switch
"""

def router_handler(rt_object, packet, packet_in):
	sourceport = packet_in.in_port
	sourcemac = packet.src
	destinmac = packet.dst
	print("========================================")
	#print(packet)		
	print("A packet from",sourcemac,"try going to",destinmac,"via",sourceport)
	protocol = packet.payload
	print(protocol)
	a = packet.find('arp')	
	if (a):
		#arp request
		if (a.opcode == arp.REQUEST):
			print("This is an ARP Request")			
			rt_object.mac_to_port[sourcemac] = sourceport
			rt_object.ip_to_mac[a.protosrc] = sourcemac
			
			#if this is passed to the router
			if (str(a.protodst) in rt_object.routermac):
				#now generate an arp reply
				print("Now generating ARP reply")
				r = arp()
				r.hwtype = a.hwtype
				r.prototype = a.prototype
                		r.hwlen = a.hwlen
                		r.protolen = a.protolen
				r.opcode = arp.REPLY
				r.hwdst = a.hwsrc
				r.hwsrc = EthAddr(rt_object.routermac[str(a.protodst)])
				r.protodst = a.protosrc
				r.protosrc = a.protodst
				e = ethernet(type=packet.type, src=r.hwsrc,dst=a.hwsrc)
				e.payload = r
				print("Sending ARP reply to",a.protosrc)
				msg = of.ofp_packet_out()
				msg.data = e.pack()
				msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        			msg.in_port = sourceport
        			rt_object.connection.send(msg)
						
				#instruct router to learn how to deal with this ARP request
				msgarp1 = of.ofp_flow_mod()
				msgarp1.match = of.ofp_match()
				msgarp1.match.dl_type = arp.PROTO_TYPE_IP
				
				#if any arp has this distination (a.sourceIP)
				#send it to a.sourceIP like r did
				print("For the future ARP request to",a.protosrc,"send to port",sourceport)
				msgarp1.match.nw_dst = a.protosrc 
				msgarp1.actions.append(of.ofp_action_dl_addr.set_src(r.hwsrc))
				msgarp1.actions.append(of.ofp_action_dl_addr.set_src(r.hwdst))
				msgarp1.actions.append(of.ofp_action_output(port = sourceport))
				rt_object.connection.send(msgarp1)

			#if this is not sent to the router
			else:	 
				# I have recorded it so I should ignore it
	 			return
		#arp reply
		elif (a.opcode == arp.REPLY):
			print("This is an ARP Request Reply")
			rt_object.mac_to_port[sourcemac] = sourceport
			rt_object.ip_to_mac[a.protosrc] = a.hwsrc
			#if this is passed to the router
			if (str(a.protodst) in rt_object.routermac):
				print("Instruct the router to remember the arp")
				msgarp2 = of.ofp_flow_mod()
                                msgarp2.match = of.ofp_match()
                                msgarp2.match.dl_type = arp.PROTO_TYPE_IP
				#if any arp has this distination (a.sourceIP)
                                #send it to a.sourceIP in the direction of a
                                print("For the future ARP request to",a.protosrc,"send to port",sourceport)
                                msgarp2.match.nw_dst = a.protosrc
                                msgarp2.actions.append(of.ofp_action_dl_addr.set_src(a.hwsrc))
                                msgarp2.actions.append(of.ofp_action_dl_addr.set_src(a.hwdst))
                                msgarp2.actions.append(of.ofp_action_output(port = sourceport))
                                rt_object.connection.send(msgarp2)
				
				#now send the ICMP message
			else:
				print("Impossibile")
		else:
			return
	
	
	if(packet.find("icmp")):
		#if it is sending to the router
		sourceip = protocol.srcip
		destinip = protocol.dstip
		if (protocol.dstip in rt_object.routermac):
			#writing replies
			i = icmp()
			i.type = icmp.TYPE_ECHO_REPLY
			i.payload = packet.find('icmp').payload
			pip = ipv4()
			pip.protocol = ipv4.ICMP_PROTOCOL
			pip.srcip = destinip
			pip.dstip = sourceip
			e = ethernet(type=packet.type, src=destinmac,dst=sourcemac)
			e.type = e.IP_TYPE
			pip.payload = i
			e.payload = pip
			msg4 = of.ofp_packet_out()
			msg4.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
			msg4.data = e.pack()
			msg4.in_port = sourceport
			rt_object.connection.send(msg4)
		else:
			# do something
			#if (protocol.dstip in rt_object.ip_to_mac)
			return			
