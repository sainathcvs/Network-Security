#! /usr/bin/python

from scapy.all import *
import dpkt
from sys import argv
import pcap

def have_common_ips(existing_ips,current_ips):
    #print "-------------have_common_ips-------------------"
    len_min = min(len(existing_ips),len(current_ips))
    if len_min == len(existing_ips):
        for i in xrange(0,len_min):
            if existing_ips[i] in current_ips:
                return True
    else:
        for i in xrange(0, len_min):
            if current_ips[i] in existing_ips:
                return True
    return False


def print_dns_attack(txID,req,ans1,ans2,timestamp):
    #print "-------------print_dns_attack-------------------"
    print timestamp,'DNS poisoning attempt'
    print 'TXID ',txID,' Request ',req
    print 'Answer1 ',ans1
    print 'Answer2 ', ans2
    print '\n'


def dns_detect(pkt):
    #print "-------------dns_detect-------------------"
    dns = pkt[DNS]
    txID = dns.id
    ans_ips=[]
    #our ip address by default
    if dns.qd[0].qtype == dpkt.dns.DNS_A and dns.qd[0].qclass == dpkt.dns.DNS_IN:
        if(dns.qr ==  dpkt.dns.DNS_Q and dns.qdcount == 1 and dns.nscount == 0 and dns.ancount == 0):
            #query packet
            if txID not in txnIDs:
                txnIDs[txID] = {'req':dns.qd[0].qname[:-1],'ips':[],'timestamp':" "}
        else:
            #answer packet
            if txID not in txnIDs.keys():
                print "if ancount----",txID,dns.ancount,dns.qd[0].qname[:-1]
                for i in xrange(0,dns.ancount):
                    ans_ips.append(dns.an[i].rdata)
                txnIDs[txID] = {'req':dns.qd[0].qname[:-1],'ips':ans_ips,'timestamp':" "}
            else:
                existing_ips = txnIDs[txID]['ips']
                timestamp = pkt.time
                #print "else ancount----",txID,dns.ancount,dns.qd[0].qname[:-1],len(existing_ips)
                for i in xrange(0,dns.ancount):
                    ans_ips.append(dns.an[i].rdata)
                if len(existing_ips)==0:
                    txnIDs[txID]['ips'] = ans_ips
                else:
                    if len(existing_ips)>0:
                        is_similar = have_common_ips(existing_ips,ans_ips)
                        if not is_similar:
                            print_dns_attack(txID,dns.qd[0].qname[:-1],existing_ips,ans_ips,timestamp)

if __name__=='__main__':
    args={}
    global txnIDs
    txnIDs={}
    interface = 'wlp3s0'
    is_interface_given = False
    global is_tracefile_given
    is_tracefile_given = False
    while argv:
        if argv[0][0] == '-':
            args[argv[0]]=argv[1]
        argv = argv[1:]
    if '-i' in args:
        is_interface_given = True
        interface = args['-i']
    if '-r' in args:
        is_tracefile_given= True
        tracefile = args['-r']
    if is_tracefile_given:
        packets = rdpcap(tracefile)
        for pkt in packets:
            if pkt.haslayer(DNS):
                dns_detect(pkt)
    else:
        pkts = sniff(iface=interface, filter="udp port 53",prn=dns_detect)