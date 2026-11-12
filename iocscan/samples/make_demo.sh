#!/bin/sh
# Creates a harmless demo tree containing a simulated "malicious" file that matches samples/iocs.txt
set -e
D=${1:-demo_tree}
mkdir -p "$D/docs" "$D/downloads/tmp"
echo "quarterly report" > "$D/docs/report.txt"
echo "MALWARE-SIMULATION-PAYLOAD-v1 (harmless test string)" > "$D/downloads/invoice_update.exe"
cp "$D/downloads/invoice_update.exe" "$D/downloads/tmp/svchost_copy.exe"
echo "Demo tree created in $D  ->  ./build/iocscan $D -i samples/iocs.txt"
