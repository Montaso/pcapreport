#!/bin/sh
# Testy end-to-end narzędzia pcapreport na syntetycznych przechwytach.
# Uruchomienie: make test
set -u

BIN=./pcapreport
OUT=out/tests
PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); printf '  [OK]   %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

check() { # opis, polecenie
    desc=$1; shift
    if "$@" >/dev/null 2>&1; then ok "$desc"; else fail "$desc"; fi
}

is_pdf() { head -c 5 "$1" | grep -q '%PDF-' && tail -c 8 "$1" | grep -q '%%EOF'; }
is_png() { [ "$(head -c 8 "$1" | od -An -tx1 | tr -d ' \n')" = "89504e470d0a1a0a" ]; }

all_outputs() { # katalog
    is_pdf "$1/raport.pdf" || return 1
    n=0
    for f in "$1"/*.png; do is_png "$f" || return 1; n=$((n + 1)); done
    [ "$n" -eq 10 ]
}

rm -rf "$OUT"
mkdir -p "$OUT"

echo "== Raporty dla przykładowych przechwytów"
for s in normal attacks; do
    $BIN -q -c -o "$OUT/$s" "samples/$s.pcap"
    check "$s.pcap: kod wyjścia 0, PDF + 10 PNG" all_outputs "$OUT/$s"
    check "$s.pcap: flows.csv zawiera przepływy" test "$(wc -l < "$OUT/$s/flows.csv")" -gt 10
done
$BIN -q -o "$OUT/mixed" samples/mixed.pcapng
check "mixed.pcapng (pcapng, VLAN, IPv6, raw IP): PDF + PNG" all_outputs "$OUT/mixed"
$BIN -q -o "$OUT/all" samples/normal.pcap samples/attacks.pcap samples/mixed.pcapng
check "kilka plików naraz" all_outputs "$OUT/all"

echo "== Wykrywanie nieprawidłowości (attacks.pcap)"
$BIN -o "$OUT/attacks2" samples/attacks.pcap > "$OUT/attacks.txt" 2>&1
for pat in "Skanowanie portów TCP: 10.0.0.66 -> 10.0.0.5" \
           "Skanowanie hostów TCP/445" \
           "SYN flood na 10.0.0.80:80" \
           "UDP flood na 10.0.0.90" \
           "Niedozwolone kombinacje flag TCP z hosta 10.0.0.66" \
           "tunel DNS" \
           "NXDOMAIN" \
           "beaconing" \
           "Duży transfer wychodzący 10.0.0.15" \
           "Telnet" \
           "TCP/4444" \
           "Zerowe okno" \
           "retransmisjami"; do
    check "wykryto: $pat" grep -q "$pat" "$OUT/attacks.txt"
done

echo "== Brak fałszywych alarmów wysokiej wagi (normal.pcap)"
$BIN -o "$OUT/normal2" samples/normal.pcap > "$OUT/normal.txt" 2>&1
check "normal.pcap: brak zdarzeń WYSOKI" sh -c "! grep -q 'WYSOKI' '$OUT/normal.txt'"

echo "== Odporność na błędne dane"
: > "$OUT/empty.pcap"
check "pusty plik -> kod błędu" sh -c "! $BIN -q -o '$OUT/e1' '$OUT/empty.pcap'"
head -c 4000 /dev/urandom > "$OUT/garbage.pcap" 2>/dev/null || dd if=/dev/zero of="$OUT/garbage.pcap" bs=1 count=4000 2>/dev/null
check "losowe dane -> kod błędu" sh -c "! $BIN -q -o '$OUT/e2' '$OUT/garbage.pcap'"
check "nieistniejący plik -> kod błędu" sh -c "! $BIN -q -o '$OUT/e3' '$OUT/brak.pcap'"
head -c 300000 samples/normal.pcap > "$OUT/truncated.pcap"
$BIN -q -o "$OUT/trunc" "$OUT/truncated.pcap"
check "obcięty plik -> raport z częściowych danych" all_outputs "$OUT/trunc"
head -c 24 samples/normal.pcap > "$OUT/header_only.pcap"
$BIN -q -o "$OUT/hdr" "$OUT/header_only.pcap"
check "sam nagłówek (0 pakietów) -> raport" all_outputs "$OUT/hdr"
check "--help" $BIN --help
check "niepoprawna opcja -> kod błędu" sh -c "! $BIN --top 0 samples/normal.pcap"

echo
echo "Wynik: $PASS OK, $FAIL błędów"
[ "$FAIL" -eq 0 ]
