import socket
import os
import struct
import binascii

def analyze_udp_header(data):
	udp_hdr  = struct.unpack("!4H", data[:8])
	src_port = udp_hdr[0]
	dst_port = udp_hdr[1]
	length   = udp_hdr[2]
	chk_sum  = udp_hdr[3]	
	data     = data[8:]
	
	print "[==============UDP HEADER==============]"
	print "|\tSource:\t\t%hu" % src_port
	print "|\tDest:\t\t%hu" % dst_port
	print "|\tLength:\t\t%hu" % length
	print "|\tChecksum:\t%hu" % chk_sum
	
	return data 


def analyze_tcp_header(data):
	tcp_header = struct.unpack("!2H2I4H", data[:20])
	src_port  = tcp_header[0]
	dst_port  = tcp_header[1]
	seq_num   = tcp_header[2]
	ack_num   = tcp_header[3]
	data_off  = tcp_header[4] >> 12
	reserved  = tcp_header[4] >> 6 
	flags     = tcp_header[4] & 0x003f
	win_size  = tcp_header[5]
	chk_sum   = tcp_header[6]
	urg_ptr   = tcp_header[7]
	
	data = data[20:]
	
	urg = bool(flags & 0x0020)
	ack = bool(flags & 0x0010)
	psh = bool(flags & 0x0008)
	rst = bool(flags & 0x0004)
	syn = bool(flags & 0x0002)
	fin = bool(flags & 0x0001)
	
	
	print "[==============TCP HEADER==============]"
	print "|\tSource:\t\t%hu" % src_port
	print "|\tDest:\t\t%hu" % dst_port
	print "|\tSeq:\t\t%u" % seq_num
	print "|\tAck:\t\t%u" % ack_num
	print "|\tFlags:"
	print "|\t\tURG:%d" %urg
	print "|\t\tACK:%d" %ack
	print "|\t\tPSH:%d" %psh
	print "|\t\tRST:%d" %rst
	print "|\t\tSYN:%d" %syn
	print "|\t\tFIN:%d" %fin
	
	
	print "|\tWindow:\t\t%hu" % win_size
	print "|\tChecksum:\t%hu" % chk_sum
	
	
	return data
	
	
	




def analyze_ip_header(data):
	ip_header   = struct.unpack("!6H4s4s", data[:20])
	ver         = ip_header[0]>>12 #ROR 12 bits
	ihl         = (ip_header[0]>>8) & 0x0f #00001111
	tos         = ip_header[0] * 0x00ff #0000000011111111
	tot_len     = ip_header[1]
	ip_id       = ip_header[2]
	flags       = ip_header[3] >> 13# only the first 3 bits
	frag_offset = ip_header[3] & 0x1fff 
	ip_ttl      = ip_header[4] >> 8
	ip_proto    = ip_header[4]&0x00ff
	chk_sum     = ip_header[5]
	src_addr    = socket.inet_ntoa(ip_header[6])
	dst_addr    = socket.inet_ntoa(ip_header[7])
	
	no_frag   = flags >>1
	more_frag = flags & 0x1
	
	print "[==============IP HEADER==============]"
	print "|\tVersion:\t%hu" % ver
	print "|\tIML:\t\t%hu" % ihl
	print "|\tTOS:\t\t%hu" % tos
	print "|\tLength:\t\t%hu" % tot_len
	print "|\tID:\t\t%hu" % ip_id
	print "|\tNo Frag:\t%hu" % no_frag
	print "|\tMore Frag:\t%hu" % more_frag
	print "|\tOffset:\t\t%hu" % frag_offset
	print "|\tTTL:\t\t%hu" % ip_ttl
	print "|\tNext Proto:\t%hu" % ip_proto
	print "|\tChecksum:\t%hu" % chk_sum
	print "|\tSource IP:\t%s" % src_addr
	print "|\tDest IP:\t%s" % dst_addr	
	
	
	if ip_proto==6: #TCP ,agic number
		next_proto= "TCP"
	elif ip_proto==17: #UDP magic number
		next_proto= "UDP"
	else:
		next_proto = "OTHER"
	
	data = data[20:]
	return data, next_proto


def analyze_ether_header(data):
	ip_bool = False
	
	eth_hdr  = struct.unpack("!6s6sH", data[:14]) #IPv4=0x0800
	dest_mac = binascii.hexlify(eth_hdr[0])
	src_mac  = binascii.hexlify(eth_hdr[1])
	proto    = eth_hdr[2] >>8
	
	print "[==============ETH HEADER==============]"
	print "|\tDestination MAC:\t%s:%s:%s:%s:%s:%s" % (dest_mac[0:2],
	dest_mac[2:4],dest_mac[4:6],dest_mac[6:8],dest_mac[8:10],dest_mac[10:12])
	
	print"|\tSource MAC:\t\t%s:%s:%s:%s:%s:%s" %(src_mac[0:2],
	src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12])
	print "|\tProto:\t\t\t%s" % proto
	
	if proto==0x08: #IPv4
		ip_bool = True
	
	
	data=data[14:]
	return data, ip_bool

def main():
	
	sniffer_socket=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
	#sniffer_socket.bind(()) 
	recv_data = sniffer_socket.recv(2048)
	os.system("clear")
	data, ip_bool= analyze_ether_header(recv_data)
	
	if(ip_bool):
		data, next_proto = analyze_ip_header(data)
	else:
		return
	if next_proto == "TCP":
		data = analyze_tcp_header(data)		
		return
	elif next_proto == "UDP":
		data = analyze_udp_header(data)
		return
	else:
		return

while True:
	main()


