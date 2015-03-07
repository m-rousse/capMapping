import pyshark
import sys
import getopt
import json
import pprint

def dnsTypes(id):
    types = {   1 : 'A',
                2 : 'NS',
                5 : 'CNAME',
                6 : 'SOA',
                12 : 'PTR',
                15 : 'MX',
                16 : 'TXT',
                17 : 'RP',
                18 : 'AFSDB',
                24 : 'SIG',
                25 : 'KEY',
                28 : 'AAAA',
                29 : 'LOC',
                33 : 'SRV',
                35 : 'NAPTR',
                36 : 'KX',
                37 : 'CERT',
                39 : 'DNAME',
                42 : 'APL',
                43 : 'DS',
                44 : 'SSHFP',
                45 : 'IPSECKEY',
                46 : 'RRSIG',
                47 : 'NSEC',
                48 : 'DNSKEY',
                49 : 'DHCID',
                50 : 'NSEC3',
                51 : 'NSEC3PARAM',
                52 : 'TLSA',
                55 : 'HIP',
                59 : 'CDS',
                60 : 'CDNSKEY',
                249 : 'TKEY',
                250 : 'TSIG',
                252 : 'AXFR',
                253 : 'MAILB',
                254 : 'MAILA',
                255 : '*',
                257 : 'CAA',
                32768 : 'TA',
                32769 : 'DLV',
                }
    if id in types.keys():
        return types[id]
    else:
        return 'Unknown'

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "i:")
    except getopt.GetoptError as err:
        usage()
        sys.exit(2)
    present = False
    for opt,arg in opts:
        if opt == '-i':
            capfile = arg
            present = True
    if not present:
        usage()
        sys.exit(2)
    cap = pyshark.FileCapture(input_file=capfile, keep_packets=False)
    i = 0
    paq = True
    hosts = {}
    while paq :
        try:
            paq = cap._packet_generator.send(None)
        except:
            paq = False
        if paq:
            i += 1
            print('Paquet '+str(i),end="\r")
            protos = paq.frame_info.protocols.split(':')
            proto = protos.pop()
            if proto in ['nbns', 'dns', 'http', 'browser', 'db-lsp-disc']:
                datas = ''
                if proto == 'nbns':
                    print("paqId "+str(i)+" - "+proto.upper()+" : "+paq.udp.port)
                elif proto == 'dns':
                    if(int(paq.udp.srcport) == 5353 or int(paq.udp.dstport) == 5353):
                        print("paqId "+str(i)+" - MDNS : "+paq.udp.port)
                    else:
                        dns_type = int(paq.dns.qry_type)
                        dns_query = dnsTypes(dns_type)
                        datas = {'type' : dns_query, 'host' : paq.dns.qry_name}
                        print("paqId "+str(i)+" - DNS : "+paq.udp.port)
                elif proto == 'http':
                    if 'udp' in protos:
                        if(int(paq.udp.srcport) == 1900 or int(paq.udp.dstport) == 1900):
                            print("paqId "+str(i)+" - SSDP : "+paq.udp.port)
                        else:
                            print("paqId "+str(i)+" - HTTP : "+paq.udp.port)
                elif proto == 'browser':
                    print("paqId "+str(i)+" - "+proto.upper()+" : "+paq.udp.port)
                elif proto == 'db-lsp-disc':
                    datas = json.loads(paq['db-lsp-disc'].db_lsp_text)
                    print("paqId "+str(i)+" - "+proto.upper())
                for layer in paq.layers:
                    if layer.layer_name == 'ip':
                        addOrUpdate(hosts, paq.ip.src,proto, datas)
                    elif layer.layer_name == 'ipv6':
                        addOrUpdate(hosts, paq.ipv6.src,proto, datas)
    cap.close()
    pp = pprint.PrettyPrinter(indent=1)
    pp.pprint(hosts)

def usage():
    print("Usage : python capMap.py -i file.cap")

def addOrUpdate(hosts, host, proto, datas):
    if host in hosts.keys():
        hosts[host][proto] = datas
        pass
        #print('IP : '+host+' est present')
    else:
        hosts[host] = {}
        hosts[host][proto] = datas
        print('IP : '+host+' ajoutee')

if __name__ == "__main__":
    main(sys.argv[1:])
