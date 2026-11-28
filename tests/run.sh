#!/bin/sh
# Unit tests for the packet code. Needs a MinGW gcc on Windows and the WinDivert package:
#   WINDIVERT=/path/to/WinDivert-2.2.2-A tests/run.sh
# The checks use WinDivert.dll only for its checksum helpers; no driver and no admin rights.
set -e
cd "$(dirname "$0")"
WD=${WINDIVERT:?set WINDIVERT to the unpacked WinDivert folder}
B=build; rm -rf $B; mkdir $B
cp "$WD/x64/WinDivert.dll" $B/
CF="-std=gnu99 -Wall -isystem $WD/include -I../src -L$WD/x64"
gcc $CF test_splitpos.c ../src/splitpos.c -o $B/splitpos.exe
gcc $CF test_send_split.c ../src/sendsplit.c ../src/splitpos.c -o $B/send_split.exe -lWinDivert -lws2_32
# fakepackets.c sends through WinDivertSend; the test swaps in its own
gcc $CF -c -DWINDIVERTEXPORT=extern -DWinDivertSend=test_send ../src/fakepackets.c -o $B/fakepackets.o
gcc $CF test_md5sig.c $B/fakepackets.o ../src/quic.c ../src/lazydll.c -o $B/md5sig.exe -lWinDivert -lws2_32
for t in splitpos send_split md5sig; do echo "== $t"; $B/$t.exe | tail -1; $B/$t.exe >/dev/null; done
