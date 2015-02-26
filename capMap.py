import pyshark
import sys
import getopt
import json

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
    while paq :
        try:
            paq = cap._packet_generator.send(None)
        except:
            print("Fin")
            paq = False
        if paq:
            i += 1
            protos = paq.frame_info.protocols.split(':')
            proto = protos.pop()
            if proto in ['nbns', 'dns', 'http', 'browser', 'db-lsp-disc']:
                if proto == 'nbns':
                    print("paqId "+str(i)+" - "+proto.upper()+" : "+paq.udp.port)
                elif proto == 'dns':
                    if(int(paq.udp.srcport) == 5353 or int(paq.udp.dstport) == 5353):
                        print("paqId "+str(i)+" - MDNS : "+paq.udp.port)
                    else:
                        print("paqId "+str(i)+" - DNS : "+paq.udp.port)
                elif proto == 'http':
                    if(int(paq.udp.srcport) == 1900 or int(paq.udp.dstport) == 1900):
                        print("paqId "+str(i)+" - SSDP : "+paq.udp.port)
                    else:
                        print("paqId "+str(i)+" - HTTP : "+paq.udp.port)
                elif proto == 'browser':
                    print("paqId "+str(i)+" - "+proto.upper()+" : "+paq.udp.port)
                elif proto == 'db-lsp-disc':
                    data = json.loads(paq['db-lsp-disc'].db_lsp_text)
                    print("paqId "+str(i)+" - "+proto.upper()+" : Version : "+'.'.join(str(x) for x in data['version']))
    print(i)
    cap.close()

def usage():
    print("Usage : python capMap.py -i file.cap")


if __name__ == "__main__":
    main(sys.argv[1:])
