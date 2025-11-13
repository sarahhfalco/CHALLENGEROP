#!/bin/sh
'''exec' "/home/sarahfalco/Scrivania/Challenge ROP risolte/venv/bin/python3" "$0" "$@"
' '''
import sys
from rpyc.cli.rpyc_classic import main
if __name__ == '__main__':
    if sys.argv[0].endswith('.exe'):
        sys.argv[0] = sys.argv[0][:-4]
    sys.exit(main())
