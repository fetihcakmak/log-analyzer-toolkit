"""
main.py — Log Analyzer Toolkit
Gün 7-8: Commit 3

Tek giriş noktası — 3 farklı log formatını otomatik tespit eder.

Kullanım:
  python main.py access.log                   # otomatik tespit
  python main.py access.log --type apache     # Manuel tip belirt
  python main.py error.log   --type nginx
  python main.py syslog      --type syslog
  python main.py *.log       --all            # tüm logları analiz et
  python main.py --demo                       # örnek loglar oluşturup analiz et
"""

import argparse
import glob
import json
import os
import sys
from pathlib import Path

from apache_analyzer import ApacheLogAnalyzer, generate_sample_log
from nginx_analyzer  import NginxErrorAnalyzer, generate_sample_nginx_error_log
from syslog_analyzer import SyslogAnalyzer, generate_sample_syslog


# ─────────────────────────────────────────────────────────────────────────────
# ANSI Renk Kodları
# ─────────────────────────────────────────────────────────────────────────────

RESET  = "\033[0m"; BOLD   = "\033[1m"; DIM    = "\033[2m"
GREEN  = "\033[92m"; YELLOW = "\033[93m"; ORANGE = "\033[33m"
RED    = "\033[91m"; DKRED  = "\033[31m"; CYAN   = "\033[96m"
GRAY   = "\033[90m"; WHITE  = "\033[97m"


# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

BANNER = f"""{BOLD}{CYAN}
╔══════════════════════════════════════════════════════════════╗
║              📋 LOG ANALYZER TOOLKIT  v1.0                  ║
║         Tek Araç — 3 Farklı Log Formatı                     ║
╠══════════════════════════════════════════════════════════════╣
║  🌐 Apache Access Log  → Trafik & Bot & Hata Analizi        ║
║  🔴 Nginx Error Log    → Upstream & Spike & Sağlık          ║
║  🖥  Syslog            → Kernel & OOM & Auth Anomali        ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Otomatik Log Tipi Tespiti
# ─────────────────────────────────────────────────────────────────────────────

def detect_log_type(path: str) -> str:
    """
    Log dosyasının tipini otomatik olarak tespit eder.

    Yöntemler:
      1. Dosya adına göre (access.log → apache, error.log → nginx, syslog → syslog)
      2. İlk satır içeriğine göre (pattern matching)
    """
    filename = Path(path).name.lower()

    # Dosya adı ipuçları
    if any(kw in filename for kw in ["access", "access_log", "apache"]):
        return "apache"
    if any(kw in filename for kw in ["error.log", "nginx", "error_log"]) and "access" not in filename:
        return "nginx"
    if any(kw in filename for kw in ["syslog", "auth.log", "auth", "kern.log", "messages"]):
        return "syslog"

    # İlk satır analizi
    try:
        opener = open
        if path.endswith(".gz"):
            import gzip
            opener = gzip.open
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            first_line = f.readline().strip()

        # Apache Combined Log Format
        if '" 2' in first_line or '" 3' in first_line or '" 4' in first_line:
            if first_line.count('"') >= 4:
                return "apache"

        # Nginx error.log format
        import re
        if re.match(r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[', first_line):
            return "nginx"

        # Syslog (RFC 3164)
        if re.match(r'[A-Z][a-z]{2}\s+\d+ \d{2}:\d{2}:\d{2} ', first_line):
            return "syslog"

        # RFC 5424
        if re.match(r'<\d+>\d+ \d{4}-\d{2}-\d{2}T', first_line):
            return "syslog"

    except Exception:
        pass

    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Analiz Çalıştırıcı
# ─────────────────────────────────────────────────────────────────────────────

def analyze_file(
    path:     str,
    log_type: str = "auto",
    json_out: bool = False,
    verbose:  bool = True,
) -> Optional[dict]:
    """
    Tek bir log dosyasını analiz eder.

    Args:
        path     : Log dosyası yolu
        log_type : "apache", "nginx", "syslog" veya "auto"
        json_out : JSON çıktı mı?
        verbose  : Detaylı rapor mu?

    Returns:
        Analiz sonucu dict'i veya None
    """
    if not os.path.exists(path):
        print(f"  {RED}❌ Dosya bulunamadı: {path}{RESET}")
        return None

    # Otomatik tip tespiti
    if log_type == "auto":
        log_type = detect_log_type(path)
        print(f"  {GRAY}Otomatik tespit: {CYAN}{log_type.upper()}{RESET}")

    if log_type == "unknown":
        print(f"  {YELLOW}⚠  Log tipi tespit edilemedi: {path}{RESET}")
        print(f"  Lütfen --type parametresi ile belirtin (apache/nginx/syslog)")
        return None

    # Analizörü seç ve çalıştır
    if log_type == "apache":
        analyzer = ApacheLogAnalyzer(path)
        analyzer.parse()
        if json_out:
            return analyzer.to_dict()
        analyzer.print_report(verbose=verbose)
        return analyzer.to_dict()

    elif log_type == "nginx":
        analyzer = NginxErrorAnalyzer(path)
        analyzer.parse()
        if json_out:
            return analyzer.to_dict()
        analyzer.print_report(verbose=verbose)
        return analyzer.to_dict()

    elif log_type == "syslog":
        analyzer = SyslogAnalyzer(path)
        analyzer.parse()
        if json_out:
            return analyzer.to_dict()
        analyzer.print_report(verbose=verbose)
        return analyzer.to_dict()

    return None


def analyze_multiple(
    paths:    list[str],
    log_type: str = "auto",
    json_out: bool = False,
    verbose:  bool = True,
) -> dict:
    """Birden fazla log dosyasını analiz eder."""
    results = {}
    print(f"\n  {BOLD}📂 {len(paths)} log dosyası analiz ediliyor...{RESET}\n")

    for path in paths:
        print(f"\n{BOLD}{CYAN}{'─' * 65}{RESET}")
        print(f"  {BOLD}📄 {path}{RESET}")
        print(f"{BOLD}{CYAN}{'─' * 65}{RESET}")

        result = analyze_file(path, log_type, json_out, verbose)
        if result:
            results[path] = result

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Demo Modu
# ─────────────────────────────────────────────────────────────────────────────

def run_demo(verbose: bool = True) -> None:
    """3 farklı log tipi için örnek dosyalar oluşturup analiz eder."""
    print(BANNER)
    print(f"  {BOLD}🎯 DEMO MODU — Örnek loglar oluşturuluyor...{RESET}\n")

    # Örnek loglar
    SAMPLES = [
        ("sample_access.log",       "apache",  generate_sample_log,                  500),
        ("sample_nginx_error.log",  "nginx",   generate_sample_nginx_error_log,       300),
        ("sample_syslog.log",       "syslog",  generate_sample_syslog,               400),
    ]

    for filename, log_type, generator, lines in SAMPLES:
        print(f"  {CYAN}→ {filename} oluşturuluyor...{RESET}")
        generator(filename, lines)

    print(f"\n  {GREEN}✅ Tüm örnek loglar hazır. Analiz başlıyor...\n{RESET}")

    for filename, log_type, _, _ in SAMPLES:
        print(f"\n{BOLD}{CYAN}{'═' * 65}{RESET}")
        print(f"  {BOLD}🔍 {filename.upper()}{RESET}")
        print(f"{BOLD}{CYAN}{'═' * 65}{RESET}")
        analyze_file(filename, log_type, verbose=verbose)

    print(f"\n  {GREEN}{BOLD}✅ Demo tamamlandı!{RESET}")
    print(f"  Gerçek log dosyaları için:")
    print(f"    {CYAN}python main.py /var/log/apache2/access.log{RESET}")
    print(f"    {CYAN}python main.py /var/log/nginx/error.log --type nginx{RESET}")
    print(f"    {CYAN}python main.py /var/log/syslog --type syslog{RESET}\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Log Analyzer Toolkit — Apache / Nginx / Syslog",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  python main.py access.log                           # otomatik tespit
  python main.py /var/log/nginx/error.log --type nginx
  python main.py /var/log/syslog --type syslog --json
  python main.py *.log --all --type auto              # tüm log dosyaları
  python main.py --demo                               # hızlı demo
  python main.py --demo --quiet                       # sessiz demo

Desteklenen Formatlar:
  apache  → Combined Log Format (access.log)
  nginx   → Nginx Error Format (error.log)
  syslog  → RFC 3164 / RFC 5424 (syslog, auth.log, kern.log)
        """
    )

    parser.add_argument("files",     nargs="*",
                        help="Analiz edilecek log dosyası/dosyaları")
    parser.add_argument("--type",    default="auto",
                        choices=["auto", "apache", "nginx", "syslog"],
                        help="Log formatı (varsayılan: otomatik tespit)")
    parser.add_argument("--all",     action="store_true",
                        help="Glob pattern ile tüm eşleşen dosyaları analiz et")
    parser.add_argument("--json",    action="store_true",
                        help="JSON formatında çıktı")
    parser.add_argument("--output",  type=str,
                        help="JSON çıktısını dosyaya kaydet")
    parser.add_argument("--quiet",   action="store_true",
                        help="Azaltılmış çıktı (sadece özet)")
    parser.add_argument("--demo",    action="store_true",
                        help="Demo modu — örnek loglar oluştur ve analiz et")

    args = parser.parse_args()

    # Demo modu
    if args.demo:
        run_demo(verbose=not args.quiet)
        return

    # Dosya listesi oluştur
    if not args.files:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    # Glob genişletme (--all)
    file_list = []
    for pattern in args.files:
        matches = glob.glob(pattern)
        if matches:
            file_list.extend(matches)
        elif os.path.exists(pattern):
            file_list.append(pattern)
        else:
            print(f"  {YELLOW}⚠  Bulunamadı: {pattern}{RESET}")

    if not file_list:
        print(f"  {RED}❌ Analiz edilecek dosya bulunamadı.{RESET}")
        sys.exit(1)

    print(BANNER)

    # Analiz
    if len(file_list) == 1:
        result = analyze_file(
            file_list[0],
            log_type=args.type,
            json_out=args.json,
            verbose=not args.quiet,
        )
        if args.json and result:
            output = json.dumps(result, indent=2, ensure_ascii=False, default=str)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output)
                print(f"  {GREEN}✅ JSON → {args.output}{RESET}")
            else:
                print(output)
    else:
        results = analyze_multiple(
            file_list,
            log_type=args.type,
            json_out=args.json,
            verbose=not args.quiet,
        )
        if args.json or args.output:
            output = json.dumps(results, indent=2, ensure_ascii=False, default=str)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output)
                print(f"  {GREEN}✅ JSON rapor → {args.output}{RESET}")
            else:
                print(output)

        # Çoklu dosya özeti
        print(f"\n{BOLD}{CYAN}{'═' * 65}{RESET}")
        print(f"{BOLD}{CYAN}  📊 GENEL ÖZET — {len(results)} dosya analiz edildi{RESET}")
        print(f"{BOLD}{CYAN}{'═' * 65}{RESET}")
        for path, result in results.items():
            dtype = result.get("file", path)
            total = result.get("total_requests") or result.get("total_entries", "?")
            health = result.get("health_score") or result.get("health_score", "")
            health_str = f"  Sağlık: {health}/100" if health else ""
            print(f"  {CYAN}{Path(path).name:<30}{RESET}  {total:>8,} kayıt{health_str}")
        print(f"{BOLD}{CYAN}{'═' * 65}{RESET}\n")


if __name__ == "__main__":
    main()
