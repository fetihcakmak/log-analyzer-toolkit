"""
apache_analyzer.py — Log Analyzer Toolkit
Gün 7-8: Commit 1

Apache Combined Log Format analizi.
access.log dosyasını okuyarak trafik istatistikleri, hata oranları,
bot tespiti ve ASCII grafikler üretir.

Combined Log Format:
  127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 \
  "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"
"""

import re
import os
import sys
import gzip
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Log Format Regex
# ─────────────────────────────────────────────────────────────────────────────

# Combined Log Format + Common Log Format
COMBINED_RE = re.compile(
    r'(?P<ip>\S+)\s+'           # IP adresi
    r'(?P<ident>\S+)\s+'        # ident (genellikle -)
    r'(?P<user>\S+)\s+'         # auth kullanıcı
    r'\[(?P<time>[^\]]+)\]\s+'  # timestamp
    r'"(?P<request>[^"]+)"\s+'  # HTTP isteği
    r'(?P<status>\d{3})\s+'     # HTTP status kodu
    r'(?P<bytes>\S+)'           # gönderilen bayt
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'  # referer + UA (opsiyonel)
)

# HTTP istek satırı
REQUEST_RE = re.compile(r'(?P<method>\w+)\s+(?P<path>\S+)\s+(?P<proto>\S+)')

# Tarih formatı
TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# Bilinen bot UA kalıpları
BOT_PATTERNS = [
    r"[Gg]ooglebot", r"[Bb]ing[Bb]ot", r"[Ss]lurfBot",
    r"[Yy]ahoo", r"DuckDuckBot", r"[Bb]aidu[Ss]pider",
    r"[Ss]emrush[Bb]ot", r"[Aa]hrefs[Bb]ot", r"[Mm]j12bot",
    r"[Ss]cranpy", r"[Pp]etalBot", r"[Aa]pple[Bb]ot",
    r"[Cc]rawl", r"[Ss]pider", r"[Bb]ot/", r"[Rr]obot",
    r"python-requests", r"[Cc]url", r"[Ww]get",
    r"[Ss]canner", r"[Nn]ikto", r"[Ss]qlmap",
]
BOT_RE = re.compile("|".join(BOT_PATTERNS))


# ─────────────────────────────────────────────────────────────────────────────
# Log Satırı Veri Yapısı
# ─────────────────────────────────────────────────────────────────────────────

class LogEntry:
    __slots__ = ["ip", "user", "timestamp", "method", "path", "proto",
                 "status", "bytes_sent", "referer", "user_agent", "is_bot", "raw"]

    def __init__(self, match: re.Match, raw: str):
        d = match.groupdict()
        self.ip         = d["ip"]
        self.user       = d["user"]
        self.bytes_sent = int(d["bytes"]) if d["bytes"] != "-" else 0
        self.referer    = d.get("referer", "")
        self.user_agent = d.get("agent", "")
        self.raw        = raw
        self.is_bot     = bool(BOT_RE.search(self.user_agent or ""))

        # Status
        try:
            self.status = int(d["status"])
        except (ValueError, TypeError):
            self.status = 0

        # Timestamp
        try:
            self.timestamp = datetime.strptime(d["time"], TIME_FORMAT)
        except Exception:
            self.timestamp = None

        # Request parsing
        req = d.get("request", "")
        m   = REQUEST_RE.match(req)
        if m:
            self.method = m.group("method")
            self.path   = m.group("path")
            self.proto  = m.group("proto")
        else:
            self.method = self.path = self.proto = ""


# ─────────────────────────────────────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_log_file(path: str) -> Iterator[LogEntry]:
    """Log dosyasını satır satır okur, ayrıştırır ve LogEntry üretir (.gz desteği)."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Dosya bulunamadı: {path}")

    opener = gzip.open if path.endswith(".gz") else open

    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = COMBINED_RE.match(line)
            if m:
                yield LogEntry(m, line)


# ─────────────────────────────────────────────────────────────────────────────
# Analiz Motoru
# ─────────────────────────────────────────────────────────────────────────────

class ApacheLogAnalyzer:
    """
    Apache access.log dosyasını kapsamlı şekilde analiz eder.

    Üretilen İstatistikler:
      • Toplam istek sayısı, benzersiz IP sayısı
      • HTTP status kodu dağılımı (2xx / 3xx / 4xx / 5xx)
      • En çok ziyaret edilen URL'ler
      • En aktif IP'ler (bot dahil / hariç)
      • Saatlik trafik dağılımı (ASCII heatmap)
      • User-agent analizi (insan vs bot)
      • En büyük dosyalar (bytes_sent)
      • Şüpheli aktivite tespiti (403 yağmuru, 404 crawler, SQLi belirtileri)
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        self._entries: list[LogEntry] = []
        self._parsed   = False

    # ── Parse ─────────────────────────────────────────────────────────────────

    def parse(self) -> "ApacheLogAnalyzer":
        print(f"  📂 Okunuyor: {self.log_path}")
        count = 0
        for entry in parse_log_file(self.log_path):
            self._entries.append(entry)
            count += 1
        self._parsed = True
        print(f"  ✅ {count:,} satır işlendi\n")
        return self

    # ── İstatistikler ─────────────────────────────────────────────────────────

    def _ensure_parsed(self):
        if not self._parsed:
            self.parse()

    def total_requests(self) -> int:
        return len(self._entries)

    def unique_ips(self) -> int:
        return len(set(e.ip for e in self._entries))

    def status_distribution(self) -> dict:
        counts: defaultdict = defaultdict(int)
        for e in self._entries:
            group = f"{e.status // 100}xx"
            counts[group] += 1
            counts[str(e.status)] += 1
        return dict(counts)

    def top_urls(self, n: int = 15) -> list[tuple[str, int]]:
        c = Counter(e.path for e in self._entries if e.path)
        return c.most_common(n)

    def top_ips(self, n: int = 10, exclude_bots: bool = False) -> list[tuple[str, int]]:
        entries = [e for e in self._entries if not (exclude_bots and e.is_bot)]
        c = Counter(e.ip for e in entries)
        return c.most_common(n)

    def top_user_agents(self, n: int = 10) -> list[tuple[str, int]]:
        c = Counter(e.user_agent for e in self._entries if e.user_agent)
        return c.most_common(n)

    def bot_vs_human(self) -> tuple[int, int]:
        bots   = sum(1 for e in self._entries if e.is_bot)
        humans = len(self._entries) - bots
        return bots, humans

    def hourly_traffic(self) -> dict[str, int]:
        counts: defaultdict = defaultdict(int)
        for e in self._entries:
            if e.timestamp:
                hour = e.timestamp.strftime("%H:00")
                counts[hour] += 1
        return dict(sorted(counts.items()))

    def top_4xx_urls(self, n: int = 10) -> list[tuple[str, int]]:
        c = Counter(e.path for e in self._entries if 400 <= e.status < 500 and e.path)
        return c.most_common(n)

    def top_5xx_urls(self, n: int = 10) -> list[tuple[str, int]]:
        c = Counter(e.path for e in self._entries if 500 <= e.status < 600 and e.path)
        return c.most_common(n)

    def top_bandwidth_urls(self, n: int = 10) -> list[tuple[str, int]]:
        url_bytes: defaultdict = defaultdict(int)
        for e in self._entries:
            if e.path:
                url_bytes[e.path] += e.bytes_sent
        return sorted(url_bytes.items(), key=lambda x: x[1], reverse=True)[:n]

    def suspicious_ips(self) -> list[dict]:
        """Şüpheli IP'leri tespit eder (çok fazla 403/404, SQLi belirtileri)."""
        ip_errors: defaultdict  = defaultdict(lambda: {"403": 0, "404": 0, "sqli": 0, "total": 0})
        SQLI_RE = re.compile(r"(union.+select|drop.+table|exec\s*\(|'--|\bor\b.+=)", re.IGNORECASE)

        for e in self._entries:
            d = ip_errors[e.ip]
            d["total"] += 1
            if e.status == 403:
                d["403"] += 1
            elif e.status == 404:
                d["404"] += 1
            if SQLI_RE.search(e.path or ""):
                d["sqli"] += 1

        suspicious = []
        for ip, stats in ip_errors.items():
            if stats["403"] >= 10 or stats["404"] >= 20 or stats["sqli"] >= 1:
                suspicious.append({"ip": ip, **stats})
        return sorted(suspicious, key=lambda x: x["total"], reverse=True)[:20]

    def error_rate(self) -> float:
        total  = len(self._entries)
        errors = sum(1 for e in self._entries if e.status >= 400)
        return (errors / total * 100) if total > 0 else 0

    # ── Raporlama ─────────────────────────────────────────────────────────────

    def print_report(self, verbose: bool = True) -> None:
        self._ensure_parsed()

        RESET  = "\033[0m"; BOLD   = "\033[1m"; DIM    = "\033[2m"
        GREEN  = "\033[92m"; YELLOW = "\033[93m"; ORANGE = "\033[33m"
        RED    = "\033[91m"; DKRED  = "\033[31m"; CYAN   = "\033[96m"
        GRAY   = "\033[90m"; WHITE  = "\033[97m"

        bots, humans = self.bot_vs_human()
        err_rate     = self.error_rate()
        status_dist  = self.status_distribution()

        print(f"\n{BOLD}{CYAN}{'╔' + '═' * 58 + '╗'}{RESET}")
        print(f"{BOLD}{CYAN}║{'  🌐 APACHE ACCESS LOG ANALİZİ':^58}║{RESET}")
        print(f"{BOLD}{CYAN}{'╠' + '═' * 58 + '╣'}{RESET}")
        print(f"{BOLD}{CYAN}║  Dosya: {Path(self.log_path).name:<51}║{RESET}")
        print(f"{BOLD}{CYAN}{'╚' + '═' * 58 + '╝'}{RESET}\n")

        # ── Genel İstatistikler ──────────────────────────────────────────────
        print(f"  {BOLD}📊 Genel İstatistikler{RESET}")
        print(f"  {'─' * 45}")
        print(f"  Toplam İstek    : {BOLD}{self.total_requests():>10,}{RESET}")
        print(f"  Benzersiz IP    : {BOLD}{self.unique_ips():>10,}{RESET}")
        print(f"  İnsan Trafiği   : {GREEN}{humans:>10,}{RESET}")
        print(f"  Bot Trafiği     : {YELLOW}{bots:>10,}{RESET}  ({bots/max(self.total_requests(),1)*100:.1f}%)")
        err_color = DKRED if err_rate > 10 else (RED if err_rate > 5 else ORANGE if err_rate > 2 else GREEN)
        print(f"  Hata Oranı      : {err_color}{err_rate:>9.1f}%{RESET}")

        # ── Status Dağılımı ─────────────────────────────────────────────────
        print(f"\n  {BOLD}📋 HTTP Status Dağılımı{RESET}")
        print(f"  {'─' * 45}")
        for group in ["2xx", "3xx", "4xx", "5xx"]:
            count = status_dist.get(group, 0)
            pct   = count / max(self.total_requests(), 1) * 100
            bar   = "█" * int(pct / 2)
            colors = {"2xx": GREEN, "3xx": CYAN, "4xx": ORANGE, "5xx": RED}
            c = colors.get(group, WHITE)
            print(f"  {c}{group}{RESET}  {c}{bar:<25}{RESET}  {count:>7,}  ({pct:.1f}%)")

        # ── En Çok Ziyaret Edilen URL'ler ───────────────────────────────────
        print(f"\n  {BOLD}🔗 En Çok Ziyaret Edilen URL'ler (Top 10){RESET}")
        print(f"  {'─' * 55}")
        for i, (url, count) in enumerate(self.top_urls(10), 1):
            url_short = url[:45] if len(url) > 45 else url
            bar       = "▓" * min(int(count / max(self.total_requests(), 1) * 200), 20)
            print(f"  {i:>3}. {CYAN}{url_short:<45}{RESET}  {bar} {count:,}")

        # ── En Aktif IP'ler ─────────────────────────────────────────────────
        print(f"\n  {BOLD}🔥 En Aktif IP'ler (Top 10, Botlar Hariç){RESET}")
        print(f"  {'─' * 45}")
        for i, (ip, count) in enumerate(self.top_ips(10, exclude_bots=True), 1):
            print(f"  {i:>3}. {YELLOW}{ip:<18}{RESET}  {count:>7,} istek")

        # ── Saatlik Trafik Heatmap ──────────────────────────────────────────
        if verbose:
            hourly = self.hourly_traffic()
            if hourly:
                print(f"\n  {BOLD}⏰ Saatlik Trafik Dağılımı{RESET}")
                print(f"  {'─' * 55}")
                max_h = max(hourly.values(), default=1)
                for hour, count in sorted(hourly.items()):
                    bar_len = int(count / max_h * 30)
                    bar     = "█" * bar_len + "░" * (30 - bar_len)
                    heat    = DKRED if bar_len > 25 else (RED if bar_len > 18 else ORANGE if bar_len > 10 else CYAN)
                    print(f"  {hour}  {heat}{bar}{RESET}  {count:,}")

        # ── 4xx Hataları ─────────────────────────────────────────────────────
        top4xx = self.top_4xx_urls(8)
        if top4xx:
            print(f"\n  {BOLD}⚠  En Çok 4xx Hatası Alan URL'ler{RESET}")
            print(f"  {'─' * 50}")
            for url, count in top4xx:
                url_short = url[:40] if len(url) > 40 else url
                print(f"  {ORANGE}{url_short:<40}{RESET}  {count:>5,}")

        # ── Şüpheli IP'ler ───────────────────────────────────────────────────
        suspicious = self.suspicious_ips()
        if suspicious:
            print(f"\n  {BOLD}🚨 Şüpheli IP'ler{RESET}")
            print(f"  {'─' * 55}")
            print(f"  {'IP':<18} {'403':>6} {'404':>6} {'SQLi':>6} {'Toplam':>8}")
            print(f"  {'─' * 55}")
            for s in suspicious[:10]:
                sqli_mark = f" {DKRED}⚠ SQLi{RESET}" if s["sqli"] > 0 else ""
                print(
                    f"  {RED}{s['ip']:<18}{RESET}"
                    f"{s['403']:>6}  {s['404']:>6}  {s['sqli']:>6}"
                    f"  {s['total']:>6}{sqli_mark}"
                )

        print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}\n")

    def to_dict(self) -> dict:
        """Tüm analiz sonuçlarını dict olarak döndürür."""
        self._ensure_parsed()
        bots, humans = self.bot_vs_human()
        return {
            "file":              self.log_path,
            "total_requests":    self.total_requests(),
            "unique_ips":        self.unique_ips(),
            "human_traffic":     humans,
            "bot_traffic":       bots,
            "error_rate_pct":    round(self.error_rate(), 2),
            "status_distribution": self.status_distribution(),
            "top_urls":          self.top_urls(20),
            "top_ips":           self.top_ips(20),
            "hourly_traffic":    self.hourly_traffic(),
            "top_4xx":           self.top_4xx_urls(10),
            "top_5xx":           self.top_5xx_urls(10),
            "suspicious_ips":    self.suspicious_ips(),
            "top_bandwidth":     self.top_bandwidth_urls(10),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Örnek Log Üretici (Test İçin)
# ─────────────────────────────────────────────────────────────────────────────

def generate_sample_log(path: str = "sample_access.log", lines: int = 500) -> None:
    """Test için örnek Apache access.log üretir."""
    import random
    from datetime import timedelta

    URLS    = ["/", "/index.html", "/about", "/contact", "/api/v1/users",
               "/static/app.js", "/static/style.css", "/favicon.ico",
               "/admin", "/wp-admin", "/.env", "/config.php",
               "/api/v1/login", "/products", "/blog/post-1"]
    IPS     = [f"192.168.1.{i}" for i in range(1, 20)] + \
              ["45.33.32.156", "74.125.224.72", "66.249.66.1",
               "157.240.214.35", "185.220.101.35", "218.92.0.198"]
    STATUS  = ([200]*60 + [301]*5 + [304]*10 + [404]*15 + [403]*5 + [500]*3 + [429]*2)
    AGENTS  = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "curl/7.68.0",
        "python-requests/2.28.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
        "Nikto/2.1.6",
        "sqlmap/1.7",
    ]

    base_time = datetime.now().replace(hour=0, minute=0, second=0)
    with open(path, "w", encoding="utf-8") as f:
        for i in range(lines):
            ip     = random.choice(IPS)
            ts     = base_time + timedelta(seconds=random.randint(0, 86400))
            method = random.choice(["GET", "GET", "GET", "POST", "HEAD"])
            url    = random.choice(URLS)
            status = random.choice(STATUS)
            size   = random.randint(100, 50000) if status == 200 else random.randint(0, 500)
            agent  = random.choice(AGENTS)
            ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
            f.write(f'{ip} - - [{ts_str}] "{method} {url} HTTP/1.1" {status} {size} '
                    f'"-" "{agent}"\n')
    print(f"  ✅ Örnek log oluşturuldu: {path} ({lines} satır)")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, json

    parser = argparse.ArgumentParser(
        description="Apache Access Log Analyzer",
        epilog="""
Örnekler:
  python apache_analyzer.py access.log
  python apache_analyzer.py /var/log/apache2/access.log --json
  python apache_analyzer.py --generate-sample   # test için örnek log
        """
    )
    parser.add_argument("logfile", nargs="?", help="Apache access.log dosyası")
    parser.add_argument("--json",            action="store_true", help="JSON çıktı")
    parser.add_argument("--quiet",           action="store_true", help="Sadece özet")
    parser.add_argument("--generate-sample", action="store_true", help="Örnek log üret")
    parser.add_argument("--sample-lines",    type=int, default=1000)
    args = parser.parse_args()

    if args.generate_sample:
        generate_sample_log("sample_access.log", args.sample_lines)
        args.logfile = "sample_access.log"

    if not args.logfile:
        parser.print_help()
        sys.exit(1)

    analyzer = ApacheLogAnalyzer(args.logfile)
    analyzer.parse()

    if args.json:
        print(json.dumps(analyzer.to_dict(), indent=2, ensure_ascii=False,
                          default=str))
    else:
        analyzer.print_report(verbose=not args.quiet)
