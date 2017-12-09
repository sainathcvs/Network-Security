#! /usr/bin/python

from scapy.all import *
import dpkt
from sys import argv
import datetime
from pytz import timezone

def have_common_ips(existing_ips,current_ips):
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


def print_dns_attack(txID,req,ans1,ans2):
    tzone = timezone('EST')
    ts = str(datetime.datetime.now(tzone))
    print ts[:-6],
    print ' DNS poisoning attempt'
    print 'TXID ',txID,' Request ',req
    print 'Answer1 ',ans1
    print 'Answer2 ', ans2
    print '\n'


def dns_detect(pkt):
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        txID = dns.id
        ans_ips=[]
        #our ip address by default
        if dns.qd[0].qtype == dpkt.dns.DNS_A and dns.qd[0].qclass == dpkt.dns.DNS_IN:
            if not (dns.qr ==  dpkt.dns.DNS_Q and dns.qdcount == 1 and dns.nscount == 0 and dns.ancount == 0):
                #answer packet
                if txID not in txnIDs.keys():
                    for i in xrange(0,dns.ancount):
                        ans_ips.append(dns.an[i].rdata)
                    txnIDs[txID] = {'ips':ans_ips}
                else:
                    existing_ips = txnIDs[txID]['ips']
                    for i in xrange(0,dns.ancount):
                        ans_ips.append(dns.an[i].rdata)
                    if len(existing_ips)==0:
                        txnIDs[txID]['ips'] = ans_ips
                    else:
                        if len(existing_ips)>0:
                            is_similar = have_common_ips(existing_ips,ans_ips)
                            if not is_similar:
                                print_dns_attack(txID,dns.qd[0].qname[:-1],existing_ips,ans_ips)

if __name__=='__main__':
    args={}
    global txnIDs
    txnIDs={}
    interface = 'wlp3s0'
    tracefile=''
    user_filter = 'udp port 53'
    is_tracefile_given = False

    if len(argv)%2==0:
        user_filter = user_filter + " and " + argv[-1]
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
    try:
        if is_tracefile_given:
            pkts = sniff(offline=tracefile, filter=user_filter,prn=dns_detect)
        else:
            pkts = sniff(iface=interface, filter=user_filter,prn=dns_detect)
    except:
        print "ERROR::Invalid command"
