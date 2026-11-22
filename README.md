# pcapreport — analizator ruchu TCP/UDP z plików pcap

Narzędzie w języku C dla systemu Linux. Analizuje komunikację **TCP i UDP** zapisaną w plikach
**pcap / pcapng** i tworzy:

* **raport PDF**: podsumowanie, statystyki, tabele, wykresy, wykryte nieprawidłowości i metodologię,
* **10 wykresów PNG** ze statystykami ruchu i charakterystyką komunikacji,
* opcjonalnie **`flows.csv`**, czyli pełną listę przepływów do dalszej analizy.

Jedyne zależności to biblioteka standardowa C, `libm` i **zlib**. Parser pcap/pcapng, dekoder
protokołów, rasteryzer wykresów (z wbudowaną czcionką bitmapową z polskimi znakami), koder PNG
i generator PDF są częścią projektu. Nie są potrzebne libpcap, cairo, gnuplot ani Python.

## Szybki start

```bash
# zależności (Debian/Ubuntu)
sudo apt install build-essential zlib1g-dev      # Fedora: gcc make zlib-devel

make                       # kompilacja -> ./pcapreport
make samples               # generuje przykładowe przechwyty w samples/
./pcapreport -c -o out/attacks samples/attacks.pcap
xdg-open out/attacks/raport.pdf
make test                  # testy end-to-end (27 przypadków)
```

Na Windows można użyć WSL albo Dockera:

```bash
docker run --rm -v "$PWD":/w -w /w gcc:13 sh -c "make && make samples && ./pcapreport -c -o out samples/attacks.pcap"
```

## Użycie

```
pcapreport [opcje] plik.pcap [plik2.pcapng ...]

  -o, --output DIR        katalog wynikowy (domyślnie: ./raport)
  -r, --report NAME       nazwa pliku PDF (domyślnie: raport.pdf)
  -c, --csv               zapisz także listę przepływów do flows.csv
  -t, --top N             liczba pozycji w rankingach (domyślnie: 10)
  -q, --quiet             nie wypisuj podsumowania na terminal
  -b, --bucket SEC        szerokość przedziału osi czasu (domyślnie: auto)
      --flow-timeout SEC  bezczynność rozdzielająca przepływy (domyślnie: 120)
      --scan-ports N      próg skanowania portów (20)
      --sweep-hosts N     próg skanowania hostów (15)
      --synflood N        min. nieudanych połączeń dla SYN flood (200)
      --udpflood-pps N    próg UDP flood w pakietach/s (500)
      --retrans PCT       próg alarmu retransmisji w % (3)
      --beacon-min N      min. liczba połączeń dla beaconingu (6)
      --exfil-mb MB       próg dużego transferu wychodzącego (10)
```

Kilka plików podanych naraz jest analizowanych łącznie, jak jeden przechwyt. Kod wyjścia jest
różny od 0, gdy żaden plik nie dał się odczytać albo zapis wyników się nie powiódł.

### Wyniki

Gotowy przykład (raport dla `samples/attacks.pcap`) jest w [`docs/przyklad/`](docs/przyklad/raport.pdf).

| Plik | Zawartość |
|---|---|
| `raport.pdf` | raport (A4, spis treści z odnośnikami, numeracja stron) |
| `01_przepustowosc.png` | przepustowość (bit/s) w czasie: TCP / UDP / inne |
| `02_pakiety_na_sekunde.png` | natężenie ruchu w pakietach/s |
| `03_protokoly.png` | udział protokołów w wolumenie (wykres pierścieniowy) |
| `04_rozmiary_pakietow.png` | histogram długości ramek dla TCP i UDP |
| `05_top_hosty.png` | najaktywniejsze adresy IP (wysłane / odebrane) |
| `06_top_uslugi.png` | usługi (protokół/port serwera) wg wolumenu |
| `07_flagi_tcp.png` | rozkład flag TCP |
| `08_stany_tcp.png` | klasyfikacja stanów połączeń TCP |
| `09_rtt_tcp.png` | histogram czasu SYN → SYN/ACK |
| `10_anomalie.png` | nieprawidłowości wg kategorii i ważności |
| `flows.csv` | (z `-c`) wszystkie przepływy z metrykami |

## Co jest analizowane

**Formaty i warstwy.** Obsługiwane są klasyczne pliki pcap (µs i ns, oba porządki bajtów)
oraz pcapng (wiele interfejsów i sekcji, `if_tsresol`, `if_tsoffset`, bloki EPB/SPB/OPB).
Dekodowane warstwy łącza to Ethernet (z VLAN 802.1Q/QinQ), Linux SLL/SLL2, BSD loopback i surowe
IPv4/IPv6. Na poziomie IP obsługiwane są IPv4 i IPv6 z nagłówkami rozszerzeń, a w warstwie
transportowej TCP, UDP i ICMP/ICMPv6. Uszkodzone lub obcięte pliki są analizowane do miejsca
uszkodzenia.

**Statystyki.** Narzędzie liczy pakiety, wolumen, czas trwania, średnią i szczytową
przepustowość, podział na protokoły, rozkład rozmiarów ramek, rankingi hostów, usług
i przepływów oraz udział IPv4/IPv6.

**TCP.** Każde połączenie jest śledzone dwukierunkowo. Analizowane są:

* uzgadnianie połączenia (handshake),
* stan końcowy: zamknięte, otwarte, zerwane, odrzucone, bez odpowiedzi, półotwarte lub przechwycone w trakcie,
* RTT uzgadniania: min, mediana, średnia, p95, maks.,
* retransmisje i luki w numeracji sekwencyjnej,
* ogłoszenia zerowego okna,
* niedozwolone kombinacje flag.

**UDP.** Raport pokazuje przepływy (w tym jednokierunkowe, bez odpowiedzi) oraz ruch DNS:
zapytania, kody odpowiedzi, najczęściej odpytywane nazwy i entropię etykiet.

**Wykrywane nieprawidłowości** (poziomy: WYSOKI / ŚREDNI / NISKI / INFO):

| Kategoria | Heurystyka |
|---|---|
| Skanowanie portów | ≥ N portów jednego celu, w większości sondy; rozpoznaje skan SYN, connect, FIN/NULL/XMAS i UDP |
| Skanowanie hostów | ten sam port na ≥ N hostach |
| SYN flood | wiele nieudanych połączeń do jednej usługi w dużym tempie, wiele źródeł (spoofing) |
| UDP flood | duże tempo datagramów do jednego hosta bez odpowiedzi |
| Niepoprawne flagi TCP | NULL, XMAS, SYN+FIN, SYN+RST |
| Nadmiar RST | host, którego ruch w dużej części to pakiety RST |
| Retransmisje / zerowe okno | odsetek retransmisji powyżej progu; połączenia z oknem 0 |
| Anomalie DNS | możliwy tunel DNS (długie, wysokoentropijne subdomeny), DGA (dużo NXDOMAIN) |
| Beaconing | połączenia do tej samej usługi w regularnych odstępach (niski współczynnik zmienności) |
| Duży transfer | duży, asymetryczny wysył danych (możliwa eksfiltracja) |
| Ryzykowne usługi | Telnet, FTP, POP3, IMAP, TFTP, SNMP, HTTP oraz porty 4444, 31337, 1337, 6667, 12345 |
| Jakość przechwytu | obcięte lub uszkodzone pakiety, fragmentacja, problemy z plikiem |

## Architektura

```
src/
  main.c          CLI (getopt_long), orkiestracja: 2 przejścia po plikach
  pcap_reader.*   własny parser pcap/pcapng (bez libpcap)
  decode.*        dekodowanie L2 -> IPv4/IPv6 -> TCP/UDP/ICMP
  analyzer.*      liczniki, oś czasu, przepływy (tablica haszująca), hosty, usługi, DNS
  anomaly.*       heurystyczne detektory nieprawidłowości
  hmap.*          tablica haszująca (adresowanie otwarte, FNV-1a)
  raster.*        rasteryzer RGB z antyaliasingiem + czcionka bitmapowa 5x7 (UTF-8, polskie znaki)
  chart.*         wykresy: liniowy, słupkowy (pionowy/poziomy, skumulowany), pierścieniowy
  png.*           koder PNG (zlib)
  charts.*        zestaw wykresów raportu
  pdf.*           generator PDF 1.4 (czcionki standardowe + kodowanie z polskimi znakami, obrazy, odnośniki)
  report.*        skład raportu PDF, podsumowanie w terminalu, eksport CSV
tools/gen_samples.c   generator syntetycznych przechwytów testowych
tests/run_tests.sh    testy end-to-end
```

Przetwarzanie odbywa się w dwóch przejściach. Pierwsze (szybkie) wyznacza zakres czasu, na tej
podstawie dobierana jest rozdzielczość osi czasu. Drugie dekoduje pakiety i aktualizuje
statystyki. Na koniec klasyfikowane są stany połączeń, uruchamiane są detektory, rysowane
wykresy i składany jest raport. Pamięć rośnie liniowo z liczbą przepływów, a nie pakietów.

## Testy

`make test` generuje deterministyczne przechwyty (`samples/`) i sprawdza:

* poprawność plików PDF i PNG,
* wykrycie każdego zaszytego ataku,
* brak alarmów WYSOKI w ruchu normalnym,
* obsługę plików pustych, losowych, obciętych i nieistniejących.

`make debug` buduje wersję z AddressSanitizer/UBSan.

## Ograniczenia

* Analiza jest pasywna i heurystyczna, a progi można zmieniać opcjami.
* Fragmenty IP nie są składane.
* Ruch szyfrowany jest oceniany wyłącznie na podstawie metadanych.
* Retransmisje widać tylko te, które zostały zarejestrowane w punkcie przechwytu.
