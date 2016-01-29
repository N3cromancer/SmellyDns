from scapy.all import *
dns_ip = {}
previd =0 
def dns_parse(pkt):
	global dns_ipc,previd
	if pkt.haslayer(DNS):
		idofpkt = pkt[DNS].id
		
		if pkt[DNS].qr == 0: # Dette er da sporsmaal flag 
			dns_ip[idofpkt] = [pkt[IP].src,pkt[DNS].qd.qname]
		
			
		
		elif pkt[DNS].qr == 1:
			
			try:
				a = dns_ip[idofpkt]
			
				if pkt[DNS].an == None:
				
					print "no response to packet with id %s" %idofpkt
					print "requested by %s wondring about %s\n" % (a[0],a[1])
					del dns_ip[idofpkt]
				else:
					print "response to query by id",idofpkt 
					print "requested by %s wondring about %s ip of thingy is %s\n" % (a[0],a[1],pkt[DNS].an.rdata)
					del dns_ip[idofpkt]
			except:
				if previd == idofpkt:
					pass
				else:
					print "invalid dns id reported"
					print "Destination name server "+pkt[IP].dst
					print "Source request "+pkt[IP].src
					print "request id\n",idofpkt

			previd = idofpkt
sniff(filter='udp port 53', iface='lo', store=0, prn=dns_parse)
