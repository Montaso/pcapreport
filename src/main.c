/*
 * pcapreport - analiza komunikacji TCP/UDP z plików pcap/pcapng,
 * generowanie raportu PDF i wykresów PNG.
 */
#include "analyzer.h"
#include "anomaly.h"
#include "charts.h"
#include "common.h"
#include "report.h"

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static void usage(FILE *f)
{
    fprintf(f,
            "Użycie: " TOOL_NAME " [opcje] plik.pcap [plik2.pcapng ...]\n"
            "\n"
            "Analizuje ruch TCP/UDP z plików pcap/pcapng i tworzy raport PDF oraz wykresy PNG.\n"
            "Wiele plików jest analizowanych łącznie (jak jeden przechwyt).\n"
            "\n"
            "Opcje wyjścia:\n"
            "  -o, --output DIR        katalog wynikowy (domyślnie: ./raport)\n"
            "  -r, --report NAME       nazwa pliku PDF (domyślnie: raport.pdf)\n"
            "  -c, --csv               zapisz także listę przepływów do flows.csv\n"
            "  -t, --top N             liczba pozycji w rankingach (domyślnie: 10)\n"
            "  -q, --quiet             nie wypisuj podsumowania na terminal\n"
            "\n"
            "Opcje analizy:\n"
            "  -b, --bucket SEC        szerokość przedziału osi czasu (domyślnie: auto)\n"
            "      --flow-timeout SEC  bezczynność rozdzielająca przepływy (domyślnie: 120)\n"
            "      --scan-ports N      próg skanowania portów (domyślnie: 20)\n"
            "      --sweep-hosts N     próg skanowania hostów (domyślnie: 15)\n"
            "      --synflood N        min. nieudanych połączeń dla SYN flood (domyślnie: 200)\n"
            "      --udpflood-pps N    próg UDP flood w pakietach/s (domyślnie: 500)\n"
            "      --retrans PCT       próg alarmu retransmisji w %% (domyślnie: 3)\n"
            "      --beacon-min N      min. liczba połączeń dla beaconingu (domyślnie: 6)\n"
            "      --exfil-mb MB       próg dużego transferu wychodzącego (domyślnie: 10)\n"
            "\n"
            "  -h, --help              pomoc\n"
            "  -V, --version           wersja\n");
}

static int mkdir_p(const char *path)
{
    char tmp[4096];
    snprintf(tmp, sizeof tmp, "%s", path);
    size_t len = strlen(tmp);
    if (len && (tmp[len - 1] == '/')) tmp[len - 1] = 0;
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
#ifdef _WIN32
        mkdir(tmp);
#else
        mkdir(tmp, 0755);
#endif
        *p = '/';
    }
#ifdef _WIN32
    if (mkdir(tmp) != 0 && errno != EEXIST) return -1;
#else
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
#endif
    return 0;
}

static long parse_long(const char *s, const char *opt, long lo, long hi)
{
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || *end || v < lo || v > hi) {
        fprintf(stderr, TOOL_NAME ": niepoprawna wartość dla %s: '%s' (zakres %ld-%ld)\n", opt, s, lo, hi);
        exit(1);
    }
    return v;
}

static double parse_double(const char *s, const char *opt, double lo)
{
    char *end;
    errno = 0;
    double v = strtod(s, &end);
    if (errno || *end || !(v >= lo)) {
        fprintf(stderr, TOOL_NAME ": niepoprawna wartość dla %s: '%s'\n", opt, s);
        exit(1);
    }
    return v;
}

int main(int argc, char **argv)
{
    const char *outdir = "raport";
    const char *pdfname = "raport.pdf";
    int topn = 10, csv = 0;
    analysis_opts_t aopts = {0, 120.0};
    detect_opts_t dopts;
    detect_opts_default(&dopts);

    enum { O_FLOWTO = 1000, O_SCAN, O_SWEEP, O_SYNF, O_UDPF, O_RETR, O_BEACON, O_EXFIL };
    static const struct option lo[] = {
        {"output", required_argument, 0, 'o'}, {"report", required_argument, 0, 'r'},
        {"csv", no_argument, 0, 'c'},          {"top", required_argument, 0, 't'},
        {"quiet", no_argument, 0, 'q'},        {"bucket", required_argument, 0, 'b'},
        {"flow-timeout", required_argument, 0, O_FLOWTO}, {"scan-ports", required_argument, 0, O_SCAN},
        {"sweep-hosts", required_argument, 0, O_SWEEP},   {"synflood", required_argument, 0, O_SYNF},
        {"udpflood-pps", required_argument, 0, O_UDPF},   {"retrans", required_argument, 0, O_RETR},
        {"beacon-min", required_argument, 0, O_BEACON},   {"exfil-mb", required_argument, 0, O_EXFIL},
        {"help", no_argument, 0, 'h'},         {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0}};

    int ch;
    while ((ch = getopt_long(argc, argv, "o:r:ct:qb:hV", lo, NULL)) != -1) {
        switch (ch) {
        case 'o': outdir = optarg; break;
        case 'r': pdfname = optarg; break;
        case 'c': csv = 1; break;
        case 't': topn = (int)parse_long(optarg, "--top", 1, 50); break;
        case 'q': g_verbose = 0; break;
        case 'b': aopts.bucket = parse_double(optarg, "--bucket", 0.0001); break;
        case O_FLOWTO: aopts.flow_timeout = parse_double(optarg, "--flow-timeout", 1); break;
        case O_SCAN: dopts.scan_ports = (int)parse_long(optarg, "--scan-ports", 2, 65535); break;
        case O_SWEEP: dopts.sweep_hosts = (int)parse_long(optarg, "--sweep-hosts", 2, 1000000); break;
        case O_SYNF: dopts.synflood_min = (int)parse_long(optarg, "--synflood", 1, 100000000); break;
        case O_UDPF: dopts.udpflood_pps = parse_double(optarg, "--udpflood-pps", 1); break;
        case O_RETR: dopts.retrans_pct = parse_double(optarg, "--retrans", 0.01); break;
        case O_BEACON: dopts.beacon_min = (int)parse_long(optarg, "--beacon-min", 3, 1000000); break;
        case O_EXFIL: dopts.exfil_bytes = (uint64_t)(parse_double(optarg, "--exfil-mb", 0.001) * 1e6); break;
        case 'h': usage(stdout); return 0;
        case 'V': printf(TOOL_NAME " " TOOL_VERSION "\n"); return 0;
        default: usage(stderr); return 1;
        }
    }
    if (optind >= argc) {
        usage(stderr);
        return 1;
    }
    char **files = argv + optind;
    int nfiles = argc - optind;

    /* pass 1: time range */
    double t0, t1;
    uint64_t total = analysis_prescan(files, nfiles, &t0, &t1);
    log_info(TOOL_NAME ": %d plik(ów), %llu pakietów", nfiles, (unsigned long long)total);

    /* pass 2: analysis */
    analysis_t an;
    analysis_init(&an, t0, t1, &aopts);
    int ok_files = 0;
    for (int i = 0; i < nfiles; i++) {
        log_info("  analiza: %s", files[i]);
        if (analysis_add_file(&an, files[i], &aopts) == 0) ok_files++;
        else {
            const file_info_t *fi = &an.files[an.nfiles - 1];
            log_warn("%s: %s", files[i], fi->errmsg);
            if (fi->packets) ok_files++;
        }
    }
    if (!ok_files) {
        fprintf(stderr, TOOL_NAME ": żaden plik wejściowy nie mógł zostać odczytany\n");
        analysis_free(&an);
        return 1;
    }
    analysis_finish(&an);

    anomaly_list_t al;
    detect_anomalies(&an, &dopts, &al);

    if (mkdir_p(outdir) != 0) {
        fprintf(stderr, TOOL_NAME ": nie można utworzyć katalogu %s: %s\n", outdir, strerror(errno));
        return 1;
    }

    chart_out_t charts[CH_COUNT];
    charts_build(&an, &al, topn, charts);
    int fails = charts_write(charts, outdir);

    report_input_t in = {&an, &al, &dopts, &aopts, charts, topn};
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", outdir, pdfname);
    int rc = 0;
    if (report_pdf(&in, path) != 0) {
        fprintf(stderr, TOOL_NAME ": nie można zapisać raportu %s\n", path);
        rc = 1;
    } else {
        log_info("  raport PDF: %s", path);
    }
    log_info("  wykresy PNG: %d plików w %s/", CH_COUNT - fails, outdir);
    if (csv) {
        snprintf(path, sizeof path, "%s/flows.csv", outdir);
        if (report_flows_csv(&an, path) != 0) {
            log_warn("nie można zapisać %s", path);
            rc = 1;
        } else {
            log_info("  przepływy CSV: %s", path);
        }
    }
    if (g_verbose) report_console(&in, stdout);

    charts_free(charts);
    anomaly_list_free(&al);
    analysis_free(&an);
    return rc || fails ? 1 : 0;
}
