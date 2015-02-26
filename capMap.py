import pyshark
import sys
import getopt

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
    cap = pyshark.FileCapture(capfile,False)
    i = 0
    while cap.next():
        i += 1
        print(i)
    cap.close()

def usage():
    print("Usage : python capMap.py -i file.cap")


if __name__ == "__main__":
    main(sys.argv[1:])