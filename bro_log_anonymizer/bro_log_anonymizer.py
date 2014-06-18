#!/usr/bin/python
import sys
from netaddr import IPNetwork, IPAddress
# Requires pycrypto for cryptopan
from cryptopan import CryptoPan
import fileinput
import md5
import string
from argparse import ArgumentParser

if __name__ == "__main__":
    c=CryptoPan("".join([chr(x) for x in range(0,32)]))
    addrfields = []
    stringfields = []
    vectoraddrfields = []
    vectorstringfields = []
    scrubstrings = set()
    networks = set()
    seperator = "\t"
    inplace = 0

    parser = ArgumentParser()
    parser.add_argument('files', nargs='*', help='specify input files')
    parser.add_argument('-o', '--output', 
        help='specify the output file.  The default is stdout')
    parser.add_argument('-c', '--cleanstrings',
        help='replace string(s) with obfuscated text, should be a comma seperated list of strings eg. -s "company name,username,otherstuff"')
    parser.add_argument('-s', '--seperator',
        help='specifiy the field seperator, defaults to \t')
    parser.add_argument('-n', '--network',
        help='only obfuscate IPs in the specified networks, should be a comma seperated list of CIDR networks')
    args = parser.parse_args()

    if not args.cleanstrings and not args.network:
        parser.print_help()
        sys.exit(1)
    
    if args.output and args.output != '-':
        sys.stdout = open(args.output, 'w')

    if args.cleanstrings:
        for s in args.cleanstrings.split(','):
            scrubstrings.add(s)

    if args.network:
        for s in args.network.split(','):
            networks.add(s)

    if args.seperator:
        seperator = args.seperator

    for line in fileinput.input(args.files):
        line = line.rstrip()
        if line.startswith('#fields'):
            types = []
        if line.startswith('#types'):
            types = line.split(seperator)
            for t in range(0,len(types)):
                offset = t-1
                if types[t] == "addr":
                    addrfields.append(offset)
                if types[t] == "string":
                    stringfields.append(offset)
                if types[t] == 'vector[string]':
                    vectorstringfields.append(offset)
                if types[t] == 'vector[addr]':
                    vectoraddrfields.append(offset)
        if not line.startswith('#'):
            fields = line.split(seperator)
            for i in addrfields:
                if len(networks) > 0:
                    for n in networks:
                        if IPAddress(fields[i]) in IPNetwork(n):
                            fields[i] = c.anonymize(fields[i])
            for i in stringfields:
                for s in scrubstrings:
                    fields[i] = string.replace(fields[i], s, md5.new(s).hexdigest()[:10])
            for i in vectorstringfields:
                strings = fields[i].split(',')
                for j in range(0,len(strings)):
                    for s in scrubstrings:
                        strings[j] = string.replace(strings[j], s, md5.new(s).hexdigest()[:10])
                    for n in networks:
                        try:
                            if IPAddress(strings[j]) in IPNetwork(n):
                                strings[j] = c.anonymize(strings[j])
                        except Exception as e:
                            pass
                fields[i] = ','.join(strings)
            for i in vectoraddrfields:
                strings = fields[i].split(',')
                for j in range(0,len(strings)):
                    for n in networks:
                        try:
                            if IPAddress(strings[j]) in IPNetwork(n):
                                strings[j] = c.anonymize(strings[j])
                        except Exception as e:
                            pass
            line = "\t".join(fields)
        print line
