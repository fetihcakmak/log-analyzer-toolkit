"""
nginx_analyzer.py — Log Analyzer Toolkit
Gün 7-8: Commit 2

Nginx error.log analizi.
Hata seviyeleri, upstream timeout, 502/504 spike tespiti ve
servis sağlık durumu değerlendirmesi.

Nginx Error Log Formatı:
  2024/01/15 10:23:45 [error] 1234#1234: *1 connect() failed (111: Connection refused)
  while connecting to upstream, client: 1.2.3.4, server: example.com,
  request: "GET / HTTP/1.1", upstream: "http://127.0.0.1:8080/", host: "example.com"
"""

import re
import sys
import gzip
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Log Format Regex
# ─────────────────────────────────────────────────────────────────────────────

# Nginx error.log satır formatı
NGINX_ERROR_RE = re.compile(
    r'(?P<year>\d{4})/(?P<month>\d{2})/(?P<day>\d{2})\s+'   # tarih
    r'(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})\s+'      # saat
    r'\[(?P<level>\w+)\]\s+'                                   # log seviyesi
    r'(?P<pid>\d+)#(?P<tid>\d+):\s+'                          # process/thread id
    r'(?:\*(?P<conn_id>\d+)\s+)?'                             # bağlantı ID (opsiyonel)
    r'(?P<message>.+)'                                         # mesaj
)

# Nginx access.log (upstream timeout tespiti için)
NGINX_ACCESS_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<agent>[^"]*)"\s*'
    r'(?:rt=(?P<req_time>[\d.]+))?\s*'           # request_time (opsiyonel)
    r'(?:uct=(?P<upstream_ct>[\d.-]+))?\s*'      # upstream_connect_time
    r'(?:uht=(?P<upstream_ht>[\d.-]+))?\s*'      # upstream_header_time
    r'(?:urt=(?P<upstream_rt>[\d.-]+))?'          # upstream_response_time
)

# Log seviyeleri (Nginx sıra)
LEVELS = ["debug", "info", "notice", "warn", "error", "crit", "alert", "emerg"]
LEVEL_ORDER = {level: i for i, level in enumerate(LEVELS)}

# Hata kategorisi kalıpları
ERROR_CATEGORIES = {
    "upstream_failed":    re.compile(r"connect\(\) failed|upstream.*failed|no live upstreams", re.I),
    "upstream_timeout":   re.compile(r"upstream timed out|upstream.*timeout", re.I),
    "502_bad_gateway":    re.compile(r"502|bad gateway", re.I),
    "504_timeout":        re.compile(r"504|gateway.*timeout", re.I),
    "permission_denied":  re.compile(r"permission denied|13: Permission", re.I),
    "file_not_found":     re.compile(r"No such file or directory|not found", re.I),
    "ssl_error":          re.compile(r"SSL.*error|handshake failed|certificate", re.I),
    "worker_crash":       re.compile(r"worker process.*exited|worker.*killed", re.I),
    "limit_exceeded":     re.compile(r"limiting requests|rate limit|too many", re.I),
    "client_abort":       re.compile(r"client.*abort|broken pipe|reset by peer", re.I),
}


# ─────────────────────────────────────────────────────────────────────────────
# Veri Yapıları
# ─────────────────────────────────────────────────────────────────────────────

class NginxErrorEntry:
    __slots__ = ["timestamp", "level", "pid", "tid", "conn_id", "message",
                 "category", "raw"]

    def __init__(self, match: re.Match, raw: str):
        d = match.groupdict()
        self.level  = d.get("level", "unknown").lower()
        self.pid    = int(d.get("pid", 0) or 0)
        self.tid    = int(d.get("tid", 0) or 0)
        self.conn_id = d.get("conn_id")
        self.message = d.get("message", "").strip()
        self.raw     = raw

        # Timestamp
        try:
            dt_str = f"{d['year']}-{d['month']}-{d['day']} {d['hour']}:{d['min']}:{d['sec']}"
            self.timestamp = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            self.timestamp = None

        # Kategori tespiti
        self.category = "other"
        for cat, pattern in ERROR_CATEGORIES.items():
            if pattern.search(self.message):
                self.category = cat
                break


# ─────────────────────────────────────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_nginx_error_log(path: str) -> Iterator[NginxErrorEntry]:
    """Nginx error.log dosyasını satır satır ayrıştırır."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Dosya bulunamadı: {path}")

    opener = gzip.open if path.endswith(".gz") else open

    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = NGINX_ERROR_RE.match(line)
            if m:
                yield NginxErrorEntry(m, line)


# ─────────────────────────────────────────────────────────────────────────────
# Analiz Motoru
# ─────────────────────────────────────────────────────────────────────────────

class NginxErrorAnalyzer:
    """
    Nginx error.log analiz motoru.

    Tespit Edilen Durumlar:
      • Hata seviyesi dağılımı (warn → emerg)
      • En sık tekrarlanan hata mesajları
      • Upstream bağlantı sorunları
      • 502/504 spike tespiti
      • SSL/TLS hataları
      • Worker çökmesi
      • Oran limiti aşımı
      • Saatlik hata yoğunluğu
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        self._entries: list[NginxErrorEntry] = []
        self._parsed  = False

    def parse(self) -> "NginxErrorAnalyzer":
        print(f"  📂 Nginx Error Log: {self.log_path}")
        count = 0
        for entry in parse_nginx_error_log(self.log_path):
            self._entries.append(entry)
            count += 1
        self._parsed = True
        print(f"  ✅ {count:,} hata kaydı işlendi\n")
        return self

    def _ensure_parsed(self):
        if not self._parsed:
            self.parse()

    # ── İstatistikler ─────────────────────────────────────────────────────────

    def level_distribution(self) -> dict[str, int]:
        counts: defaultdict = defaultdict(int)
        for e in self._entries:
            counts[e.level] += 1
        return dict(sorted(counts.items(), key=lambda x: LEVEL_ORDER.get(x[0], 99)))

    def category_distribution(self) -> dict[str, int]:
        counts: defaultdict = defaultdict(int)
        for e in self._entries:
            counts[e.category] += 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))

    def top_errors(self, n: int = 15) -> list[tuple[str, int]]:
        """En sık tekrarlanan hata mesajları (normalize edilmiş)."""
        normalized = []
        IP_RE   = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        PORT_RE = re.compile(r':\d{2,5}')
        ID_RE   = re.compile(r'\*\d+')
        for e in self._entries:
            msg = IP_RE.sub('<IP>', e.message)
            msg = PORT_RE.sub(':<PORT>', msg)
            msg = ID_RE.sub('*<ID>', msg)
            msg = msg[:120]
            normalized.append(msg)
        c = Counter(normalized)
        return c.most_common(n)

    def hourly_errors(self) -> dict[str, int]:
        counts: defaultdict = defaultdict(int)
        for e in self._entries:
            if e.timestamp:
                counts[e.timestamp.strftime("%H:00")] += 1
        return dict(sorted(counts.items()))

    def hourly_by_level(self, level: str) -> dict[str, int]:
        counts: defaultdict = defaultdict(int)
        for e in self._entries:
            if e.level == level and e.timestamp:
                counts[e.timestamp.strftime("%H:00")] += 1
        return dict(sorted(counts.items()))

    def upstream_issues(self) -> dict:
        """Upstream bağlantı sorunu istatistikleri."""
        upstreams: defaultdict = defaultdict(int)
        UP_RE = re.compile(r'upstream:\s*"([^"]+)"')
        for e in self._entries:
            if e.category in ("upstream_failed", "upstream_timeout"):
                m = UP_RE.search(e.message)
                if m:
                    upstreams[m.group(1)] += 1

        timeouts = sum(1 for e in self._entries if e.category == "upstream_timeout")
        failed   = sum(1 for e in self._entries if e.category == "upstream_failed")
        return {
            "total_upstream_errors": timeouts + failed,
            "upstream_timeouts":     timeouts,
            "upstream_failed":       failed,
            "problematic_upstreams": dict(sorted(
                upstreams.items(), key=lambda x: x[1], reverse=True
            )[:10]),
        }

    def detect_spikes(self, window_minutes: int = 5, threshold: int = 10) -> list[dict]:
        """
        Kısa zaman diliminde çok sayıda hata tespiti (spike).

        Returns:
            [{"time": str, "count": int, "level": str}, ...]
        """
        if not self._entries:
            return []

        # Zaman bazlı gruplama (5 dakikalık pencereler)
        windows: defaultdict = defaultdict(list)
        for e in self._entries:
            if e.timestamp:
                # Pencereye yuvarlama
                minutes = (e.timestamp.hour * 60 + e.timestamp.minute)
                window  = minutes - (minutes % window_minutes)
                key     = f"{e.timestamp.strftime('%Y-%m-%d')} {window // 60:02d}:{window % 60:02d}"
                windows[key].append(e.level)

        spikes = []
        for window_time, levels in windows.items():
            count = len(levels)
            if count >= threshold:
                level_counts = Counter(levels)
                worst = max(level_counts, key=lambda l: LEVEL_ORDER.get(l, 0))
                spikes.append({
                    "time":       window_time,
                    "count":      count,
                    "worst_level": worst,
                    "breakdown":  dict(level_counts),
                })
        return sorted(spikes, key=lambda x: x["count"], reverse=True)

    def health_score(self) -> tuple[int, str]:
        """
        Servis sağlık skoru (0-100).
        
        Returns:
            (score, description)
        """
        total  = len(self._entries)
        if total == 0:
            return 100, "Hata kaydı yok — Mükemmel"

        criticals = sum(1 for e in self._entries if e.level in ("crit", "alert", "emerg"))
        errors    = sum(1 for e in self._entries if e.level == "error")
        upstreams = sum(1 for e in self._entries if e.category in ("upstream_failed", "upstream_timeout"))
        workers   = sum(1 for e in self._entries if e.category == "worker_crash")

        score = 100
        score -= min(criticals * 5, 30)
        score -= min(int(errors / total * 30), 25)
        score -= min(upstreams * 2, 20)
        score -= min(workers * 10, 20)
        score  = max(0, score)

        if score >= 90:
            desc = "🟢 Mükemmel"
        elif score >= 70:
            desc = "🟡 İyi"
        elif score >= 50:
            desc = "🟠 Orta"
        elif score >= 30:
            desc = "🔴 Kötü"
        else:
            desc = "💀 Kritik"
        return score, desc

    # ── Raporlama ─────────────────────────────────────────────────────────────

    def print_report(self, verbose: bool = True) -> None:
        self._ensure_parsed()

        RESET  = "\033[0m"; BOLD   = "\033[1m"
        GREEN  = "\033[92m"; YELLOW = "\033[93m"; ORANGE = "\033[33m"
        RED    = "\033[91m"; DKRED  = "\033[31m"; CYAN   = "\033[96m"
        GRAY   = "\033[90m"; WHITE  = "\033[97m"

        LEVEL_COLORS = {
            "debug":  GRAY, "info": GREEN, "notice": CYAN,
            "warn":   YELLOW, "error": ORANGE,
            "crit":   RED, "alert": DKRED, "emerg": DKRED,
        }

        score, score_desc = self.health_score()

        print(f"\n{BOLD}{CYAN}{'╔' + '═' * 58 + '╗'}{RESET}")
        print(f"{BOLD}{CYAN}║{'  🔴 NGINX ERROR LOG ANALİZİ':^58}║{RESET}")
        print(f"{BOLD}{CYAN}{'╠' + '═' * 58 + '╣'}{RESET}")
        print(f"{BOLD}{CYAN}║  Dosya: {Path(self.log_path).name:<51}║{RESET}")
        print(f"{BOLD}{CYAN}{'╚' + '═' * 58 + '╝'}{RESET}\n")

        # Sağlık Skoru
        score_color = GREEN if score >= 70 else (ORANGE if score >= 40 else RED)
        print(f"  {BOLD}Servis Sağlık Skoru{RESET}: {score_color}{BOLD}{score}/100{RESET}  {score_desc}")
        print(f"  Toplam Hata Kaydı: {BOLD}{len(self._entries):,}{RESET}\n")

        # Seviye Dağılımı
        print(f"  {BOLD}🔎 Hata Seviyesi Dağılımı{RESET}")
        print(f"  {'─' * 45}")
        level_dist = self.level_distribution()
        max_l = max(level_dist.values(), default=1)
        for level, count in level_dist.items():
            bar    = "█" * int(count / max_l * 25)
            color  = LEVEL_COLORS.get(level, WHITE)
            pct    = count / len(self._entries) * 100
            print(f"  {color}{level:<8}{RESET}  {color}{bar:<25}{RESET}  {count:>6,} ({pct:.1f}%)")

        # Kategori Dağılımı
        print(f"\n  {BOLD}📂 Hata Kategorisi{RESET}")
        print(f"  {'─' * 45}")
        for cat, count in self.category_distribution().items():
            print(f"  {YELLOW}{cat:<25}{RESET}  {count:>6,}")

        # Upstream Sorunları
        upstream = self.upstream_issues()
        if upstream["total_upstream_errors"] > 0:
            print(f"\n  {BOLD}🔗 Upstream Sorunları{RESET}")
            print(f"  {'─' * 45}")
            print(f"  Toplam  : {RED}{upstream['total_upstream_errors']}{RESET}")
            print(f"  Timeout : {RED}{upstream['upstream_timeouts']}{RESET}")
            print(f"  Başarısız: {RED}{upstream['upstream_failed']}{RESET}")
            if upstream["problematic_upstreams"]:
                print(f"\n  Sorunlu Upstream'ler:")
                for up, cnt in list(upstream["problematic_upstreams"].items())[:5]:
                    print(f"    {ORANGE}{up[:50]:<50}{RESET}  {cnt}")

        # En Sık Hatalar
        print(f"\n  {BOLD}📋 En Sık Tekrarlanan Hatalar (Top 10){RESET}")
        print(f"  {'─' * 55}")
        for i, (msg, count) in enumerate(self.top_errors(10), 1):
            msg_short = msg[:55] if len(msg) > 55 else msg
            print(f"  {i:>3}. {ORANGE}{msg_short:<55}{RESET}  {count:>5,}x")

        # Spike Tespiti
        if verbose:
            spikes = self.detect_spikes()
            if spikes:
                print(f"\n  {BOLD}⚡ Hata Spike'ları (5 dakikalık pencere){RESET}")
                print(f"  {'─' * 45}")
                for spike in spikes[:5]:
                    wl     = spike["worst_level"]
                    color  = LEVEL_COLORS.get(wl, WHITE)
                    print(
                        f"  {GRAY}{spike['time']}{RESET}  "
                        f"{color}{spike['count']:>4} hata{RESET}  "
                        f"(en kötü: {color}{wl}{RESET})"
                    )

        # Saatlik Dağılım
        if verbose:
            hourly = self.hourly_errors()
            if hourly:
                print(f"\n  {BOLD}⏰ Saatlik Hata Dağılımı{RESET}")
                print(f"  {'─' * 50}")
                max_h = max(hourly.values(), default=1)
                for hour, count in sorted(hourly.items()):
                    bar_len = int(count / max_h * 28)
                    bar     = "█" * bar_len + "░" * (28 - bar_len)
                    c       = DKRED if bar_len > 20 else (RED if bar_len > 14 else ORANGE if bar_len > 7 else GRAY)
                    print(f"  {hour}  {c}{bar}{RESET}  {count}")

        print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}\n")

    def to_dict(self) -> dict:
        self._ensure_parsed()
        score, score_desc = self.health_score()
        return {
            "file":              self.log_path,
            "total_entries":     len(self._entries),
            "health_score":      score,
            "health_status":     score_desc,
            "level_distribution": self.level_distribution(),
            "category_distribution": self.category_distribution(),
            "top_errors":        self.top_errors(20),
            "hourly_errors":     self.hourly_errors(),
            "upstream_issues":   self.upstream_issues(),
            "spikes":            self.detect_spikes(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Örnek Log Üretici
# ─────────────────────────────────────────────────────────────────────────────

def generate_sample_nginx_error_log(path: str = "sample_error.log", lines: int = 300) -> None:
    """Test için örnek Nginx error.log üretir."""
    import random

    TEMPLATES = [
        ("[error]", "connect() failed (111: Connection refused) while connecting to upstream, "
                    "client: {ip}, server: example.com, upstream: \"http://127.0.0.1:8080/\""),
        ("[warn]",  "upstream response is buffered to a temporary file /tmp/nginx/proxy_temp"),
        ("[error]", "*{conn} upstream timed out (110: Connection timed out) while reading response header "
                    "from upstream, client: {ip}, upstream: \"http://10.0.0.1:9000/api\""),
        ("[crit]",  "SSL_do_handshake() failed (SSL: error:0A000412:SSL routines::sslv3 alert bad certificate)"),
        ("[notice]","signal process started"),
        ("[error]", "*{conn} open() \"/var/www/html{path}\" failed (2: No such file or directory)"),
        ("[warn]",  "*{conn} limiting requests, excess: 1.800 by zone \"api_limit\", client: {ip}"),
        ("[error]", "*{conn} recv() failed (104: Connection reset by peer) while reading response"),
        ("[alert]", "worker process 12345 exited on signal 11"),
        ("[emerg]", "bind() to 0.0.0.0:443 failed (98: Address already in use)"),
        ("[error]", "*{conn} permission denied while reading upstream, client: {ip}"),
    ]

    IPS   = [f"10.0.{random.randint(0,5)}.{random.randint(1,254)}" for _ in range(20)] + \
            ["185.220.101.35", "218.92.0.198", "45.33.32.156"]
    PATHS = ["/index.html", "/api/v1/users", "/.env", "/config.php", "/admin"]

    base = datetime.now().replace(hour=0, minute=0, second=0)

    with open(path, "w", encoding="utf-8") as f:
        for i in range(lines):
            ts   = base + timedelta(seconds=random.randint(0, 86400))
            level_msg, msg_tpl = random.choice(TEMPLATES)
            ip   = random.choice(IPS)
            conn = random.randint(1, 9999)
            url  = random.choice(PATHS)
            msg  = msg_tpl.replace("{ip}", ip).replace("{conn}", str(conn)).replace("{path}", url)
            pid  = random.randint(1000, 9999)
            f.write(f"{ts.strftime('%Y/%m/%d %H:%M:%S')} {level_msg} {pid}#{pid}: *{conn} {msg}\n")

    print(f"  ✅ Örnek Nginx error.log oluşturuldu: {path} ({lines} satır)")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, json

    parser = argparse.ArgumentParser(
        description="Nginx Error Log Analyzer",
        epilog="""
Örnekler:
  python nginx_analyzer.py error.log
  python nginx_analyzer.py /var/log/nginx/error.log --json
  python nginx_analyzer.py --generate-sample
        """
    )
    parser.add_argument("logfile",           nargs="?", help="Nginx error.log dosyası")
    parser.add_argument("--json",            action="store_true")
    parser.add_argument("--quiet",           action="store_true")
    parser.add_argument("--generate-sample", action="store_true")
    parser.add_argument("--sample-lines",    type=int, default=500)
    args = parser.parse_args()

    if args.generate_sample:
        generate_sample_nginx_error_log("sample_nginx_error.log", args.sample_lines)
        args.logfile = "sample_nginx_error.log"

    if not args.logfile:
        parser.print_help()
        sys.exit(1)

    analyzer = NginxErrorAnalyzer(args.logfile)
    analyzer.parse()

    if args.json:
        print(json.dumps(analyzer.to_dict(), indent=2, ensure_ascii=False, default=str))
    else:
        analyzer.print_report(verbose=not args.quiet)
