"""
syslog_analyzer.py — Log Analyzer Toolkit
Gün 7-8: Commit 3

Syslog analizi (RFC 3164 + RFC 5424).
Kernel panic, OOM killer, servis restart döngüleri,
cron anomalileri ve genel sistem sağlık tespiti.

RFC 3164 Format:
  Jan 15 10:23:45 hostname sshd[1234]: Failed password for root from 1.2.3.4 port 5678 ssh2

RFC 5424 Format:
  <14>1 2024-01-15T10:23:45.123Z hostname sshd 1234 - - Failed password for root
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

# RFC 3164 — Klasik syslog (BSD format, /var/log/syslog, auth.log)
RFC3164_RE = re.compile(
    r'(?P<month>[A-Za-z]{3})\s+'
    r'(?P<day>\s?\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s+'
    r'(?P<message>.+)'
)

# RFC 5424 — Yeni format
RFC5424_RE = re.compile(
    r'<(?P<pri>\d+)>(?P<version>\d+)\s+'
    r'(?P<timestamp>\S+)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<app>\S+)\s+'
    r'(?P<pid>\S+)\s+'
    r'(?P<msgid>\S+)\s+'
    r'(?P<structured_data>\S+)\s+'
    r'(?P<message>.+)'
)

# Syslog severity → isim (RFC 5424)
SEVERITY_NAMES = {
    0: "EMERG", 1: "ALERT", 2: "CRIT", 3: "ERROR",
    4: "WARN",  5: "NOTICE",6: "INFO", 7: "DEBUG",
}

# Facility → isim
FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth",
    5: "syslog", 6: "lpr", 7: "news", 8: "uucp", 9: "cron",
    10: "authpriv", 11: "ftp", 16: "local0", 17: "local1",
}

# Anomali kalıpları
ANOMALY_PATTERNS: dict[str, re.Pattern] = {
    "kernel_panic":      re.compile(r"kernel panic|Oops:|BUG: |general protection fault", re.I),
    "oom_killer":        re.compile(r"Out of memory|Killed process|oom.kill", re.I),
    "disk_error":        re.compile(r"I/O error|disk error|filesystem error|EXT4-fs error", re.I),
    "service_restart":   re.compile(r"started|stopped|restarted|failed.*start|start request", re.I),
    "auth_failure":      re.compile(r"Failed password|authentication failure|Invalid user", re.I),
    "ssh_brute":         re.compile(r"Failed password.*(from \d+\.\d+)", re.I),
    "sudo_attempt":      re.compile(r"sudo:|su:", re.I),
    "cron_error":        re.compile(r"cron\[.*\].*error|cron.*failed|FAILED.cron", re.I),
    "network_error":     re.compile(r"network.*unreachable|no route|link.*down", re.I),
    "segfault":          re.compile(r"segfault|segmentation fault", re.I),
    "high_load":         re.compile(r"load average|high load", re.I),
    "disk_full":         re.compile(r"No space left|disk.*full|ENOSPC", re.I),
    "ntp_sync":          re.compile(r"ntpd|chronyd.*sync|time.*adjust", re.I),
}


# ─────────────────────────────────────────────────────────────────────────────
# Veri Yapısı
# ─────────────────────────────────────────────────────────────────────────────

class SyslogEntry:
    __slots__ = ["timestamp", "host", "process", "pid", "message",
                 "severity", "facility", "anomaly_type", "raw", "format"]

    MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
               "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

    def __init__(self, match: re.Match, fmt: str, raw: str):
        d = match.groupdict()
        self.raw     = raw
        self.format  = fmt

        if fmt == "rfc3164":
            self._parse_3164(d)
        else:
            self._parse_5424(d)

        # Anomali tespiti
        self.anomaly_type = None
        for atype, pattern in ANOMALY_PATTERNS.items():
            if pattern.search(self.message or ""):
                self.anomaly_type = atype
                break

    def _parse_3164(self, d: dict):
        self.host    = d.get("host", "unknown")
        self.process = d.get("process", "")
        self.pid     = int(d.get("pid") or 0)
        self.message = d.get("message", "")
        self.severity = None
        self.facility = None

        try:
            month = self.MONTHS.get(d["month"], 1)
            day   = int(d["day"].strip())
            time_parts = d["time"].split(":")
            self.timestamp = datetime(
                datetime.now().year, month, day,
                int(time_parts[0]), int(time_parts[1]), int(time_parts[2])
            )
        except Exception:
            self.timestamp = None

    def _parse_5424(self, d: dict):
        self.host    = d.get("host", "unknown")
        self.process = d.get("app", "")
        self.message = d.get("message", "")
        try:
            self.pid = int(d.get("pid") or 0)
        except Exception:
            self.pid = 0

        pri = int(d.get("pri", 13))
        self.facility = pri >> 3
        self.severity = pri & 7

        try:
            self.timestamp = datetime.fromisoformat(
                d["timestamp"].replace("Z", "+00:00")
            )
        except Exception:
            self.timestamp = None


# ─────────────────────────────────────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_syslog(path: str) -> Iterator[SyslogEntry]:
    """Syslog dosyasını ayrıştırır (RFC 3164 + RFC 5424)."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Dosya bulunamadı: {path}")

    opener = gzip.open if path.endswith(".gz") else open

    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # RFC 5424 dene
            m = RFC5424_RE.match(line)
            if m:
                yield SyslogEntry(m, "rfc5424", line)
                continue

            # RFC 3164 dene
            m = RFC3164_RE.match(line)
            if m:
                yield SyslogEntry(m, "rfc3164", line)


# ─────────────────────────────────────────────────────────────────────────────
# Analiz Motoru
# ─────────────────────────────────────────────────────────────────────────────

class SyslogAnalyzer:
    """
    Syslog anomali tespit ve analiz motoru.

    Tespit Edilen Durumlar:
      • Kernel panic / OOM killer
      • Disk hataları / doluluk
      • Servis restart döngüleri
      • Auth başarısızlıkları (SSH brute force dahil)
      • Cron anomalileri
      • Ağ bağlantı sorunları
      • Segfault (uygulama çöküşü)
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        self._entries: list[SyslogEntry] = []
        self._parsed  = False

    def parse(self) -> "SyslogAnalyzer":
        print(f"  📂 Syslog: {self.log_path}")
        count = 0
        for entry in parse_syslog(self.log_path):
            self._entries.append(entry)
            count += 1
        self._parsed = True
        print(f"  ✅ {count:,} satır işlendi\n")
        return self

    def _ensure_parsed(self):
        if not self._parsed:
            self.parse()

    # ── İstatistikler ─────────────────────────────────────────────────────────

    def process_distribution(self, n: int = 15) -> list[tuple[str, int]]:
        c = Counter(e.process for e in self._entries if e.process)
        return c.most_common(n)

    def anomaly_distribution(self) -> dict[str, int]:
        counts: defaultdict = defaultdict(int)
        for e in self._entries:
            if e.anomaly_type:
                counts[e.anomaly_type] += 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))

    def get_anomaly_events(self, anomaly_type: str, n: int = 10) -> list[SyslogEntry]:
        return [e for e in self._entries if e.anomaly_type == anomaly_type][:n]

    def service_restart_analysis(self) -> dict[str, int]:
        """Hangi servisler kaç kez yeniden başlatıldı?"""
        restarts: defaultdict = defaultdict(int)
        RESTART_RE = re.compile(
            r"(?:started|stopped|restarted|start request repeated too quickly)",
            re.I
        )
        SERVICE_RE = re.compile(r"systemd\[\d+\]|service|unit", re.I)
        for e in self._entries:
            if RESTART_RE.search(e.message or "") and SERVICE_RE.search(e.message or ""):
                # Servis adını çıkar
                m = re.search(r"'?([\w\-]+\.service)'?", e.message or "")
                if m:
                    restarts[m.group(1)] += 1
        return dict(sorted(restarts.items(), key=lambda x: x[1], reverse=True)[:15])

    def auth_failure_analysis(self) -> dict:
        """Auth başarısızlıklarını analiz eder."""
        failures_by_ip: defaultdict = defaultdict(int)
        failures_by_user: defaultdict = defaultdict(int)
        total = 0

        IP_RE   = re.compile(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})')
        USER_RE = re.compile(r'for\s+(?:invalid user\s+)?(\w+)\s+from')

        for e in self._entries:
            if e.anomaly_type == "auth_failure":
                total += 1
                m = IP_RE.search(e.message or "")
                if m:
                    failures_by_ip[m.group(1)] += 1
                m = USER_RE.search(e.message or "")
                if m:
                    failures_by_user[m.group(1)] += 1

        return {
            "total_failures": total,
            "top_attacking_ips": sorted(
                failures_by_ip.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "targeted_usernames": sorted(
                failures_by_user.items(), key=lambda x: x[1], reverse=True
            )[:10],
        }

    def oom_events(self) -> list[dict]:
        """OOM killer olaylarını listeler."""
        events = []
        for e in self._entries:
            if e.anomaly_type == "oom_killer":
                proc_m = re.search(r"Killed process (\d+) \(([^)]+)\)", e.message or "")
                events.append({
                    "timestamp": e.timestamp.isoformat() if e.timestamp else "?",
                    "process":   proc_m.group(2) if proc_m else "?",
                    "pid":       proc_m.group(1) if proc_m else "?",
                    "message":   e.message[:100],
                })
        return events

    def hourly_distribution(self) -> dict[str, int]:
        counts: defaultdict = defaultdict(int)
        for e in self._entries:
            if e.timestamp:
                counts[e.timestamp.strftime("%H:00")] += 1
        return dict(sorted(counts.items()))

    def critical_events(self) -> list[SyslogEntry]:
        """Acil müdahale gerektiren olayları listeler."""
        CRITICAL_TYPES = {"kernel_panic", "oom_killer", "disk_full", "segfault", "disk_error"}
        return [e for e in self._entries if e.anomaly_type in CRITICAL_TYPES]

    def system_health_score(self) -> tuple[int, str]:
        """Sistem sağlık skoru."""
        total = len(self._entries)
        if total == 0:
            return 100, "🟢 Mükemmel"

        anomaly_dist = self.anomaly_distribution()
        score = 100

        score -= anomaly_dist.get("kernel_panic", 0) * 50
        score -= anomaly_dist.get("oom_killer", 0) * 20
        score -= anomaly_dist.get("disk_full", 0) * 30
        score -= anomaly_dist.get("disk_error", 0) * 15
        score -= anomaly_dist.get("segfault", 0) * 5
        score -= min(anomaly_dist.get("auth_failure", 0) // 10, 20)
        score -= anomaly_dist.get("service_restart", 0) * 2
        score  = max(0, score)

        if score >= 90:
            desc = "🟢 Mükemmel"
        elif score >= 70:
            desc = "🟡 İyi"
        elif score >= 40:
            desc = "🟠 Orta"
        elif score > 0:
            desc = "🔴 Kötü"
        else:
            desc = "💀 Kritik"
        return score, desc

    # ── Raporlama ─────────────────────────────────────────────────────────────

    def print_report(self, verbose: bool = True) -> None:
        self._ensure_parsed()

        RESET  = "\033[0m"; BOLD  = "\033[1m"
        GREEN  = "\033[92m"; YELLOW= "\033[93m"; ORANGE = "\033[33m"
        RED    = "\033[91m"; DKRED = "\033[31m"; CYAN   = "\033[96m"
        GRAY   = "\033[90m"; WHITE = "\033[97m"

        ANOMALY_COLORS = {
            "kernel_panic": DKRED, "oom_killer": DKRED, "disk_full": DKRED,
            "disk_error":   RED,   "segfault":   RED,   "service_restart": ORANGE,
            "auth_failure": ORANGE,"ssh_brute":  RED,   "cron_error": YELLOW,
            "network_error": ORANGE,"high_load": YELLOW, "other": GRAY,
        }
        ANOMALY_ICONS = {
            "kernel_panic": "💀", "oom_killer": "🔴", "disk_full": "💾",
            "disk_error":   "⚠️ ", "segfault":   "💥", "service_restart": "🔄",
            "auth_failure": "🔐", "ssh_brute":  "🚨", "cron_error": "⏰",
            "network_error":"🌐", "high_load":  "📈", "disk_error": "💾",
        }

        score, score_desc = self.system_health_score()
        score_color = GREEN if score >= 70 else (ORANGE if score >= 40 else RED)

        print(f"\n{BOLD}{CYAN}{'╔' + '═' * 58 + '╗'}{RESET}")
        print(f"{BOLD}{CYAN}║{'  🖥  SYSLOG ANALİZİ & ANOMALİ TESPİTİ':^58}║{RESET}")
        print(f"{BOLD}{CYAN}{'╠' + '═' * 58 + '╣'}{RESET}")
        print(f"{BOLD}{CYAN}║  Dosya: {Path(self.log_path).name:<51}║{RESET}")
        print(f"{BOLD}{CYAN}{'╚' + '═' * 58 + '╝'}{RESET}\n")

        print(f"  {BOLD}Sistem Sağlık Skoru{RESET}: {score_color}{BOLD}{score}/100{RESET}  {score_desc}")
        print(f"  Toplam Kayıt: {BOLD}{len(self._entries):,}{RESET}\n")

        # Anomali Dağılımı
        anom = self.anomaly_distribution()
        print(f"  {BOLD}🔍 Tespit Edilen Anomaliler{RESET}")
        print(f"  {'─' * 50}")
        if anom:
            max_a = max(anom.values())
            for atype, count in anom.items():
                icon  = ANOMALY_ICONS.get(atype, "❓")
                color = ANOMALY_COLORS.get(atype, GRAY)
                bar   = "█" * int(count / max_a * 20)
                print(f"  {icon} {color}{atype:<22}{RESET}  {bar:<20}  {count:>5,}")
        else:
            print(f"  {GREEN}✅ Anomali tespit edilmedi{RESET}")

        # Kritik Olaylar
        critical = self.critical_events()
        if critical:
            print(f"\n  {BOLD}{DKRED}🚨 KRİTİK OLAYLAR ({len(critical)} adet){RESET}")
            print(f"  {'─' * 55}")
            for e in critical[:5]:
                ts = e.timestamp.strftime("%m-%d %H:%M:%S") if e.timestamp else "?"
                print(f"  {DKRED}{ts}{RESET}  {e.process:<15}  {e.message[:50]}")

        # Auth Analizi
        auth = self.auth_failure_analysis()
        if auth["total_failures"] > 0:
            print(f"\n  {BOLD}🔐 Auth Başarısızlıkları{RESET}")
            print(f"  {'─' * 45}")
            print(f"  Toplam: {RED}{auth['total_failures']}{RESET}")
            if auth["top_attacking_ips"]:
                print(f"\n  En Çok Saldıran IP'ler:")
                for ip, cnt in auth["top_attacking_ips"][:5]:
                    print(f"    {ORANGE}{ip:<20}{RESET}  {cnt} deneme")
            if auth["targeted_usernames"]:
                print(f"\n  Hedef Alınan Kullanıcılar:")
                for user, cnt in auth["targeted_usernames"][:5]:
                    print(f"    {YELLOW}{user:<20}{RESET}  {cnt}x")

        # OOM Olayları
        oom = self.oom_events()
        if oom:
            print(f"\n  {BOLD}{DKRED}🔴 OOM Killer Olayları ({len(oom)} adet){RESET}")
            print(f"  {'─' * 45}")
            for event in oom[:5]:
                print(f"  {DKRED}{event['timestamp'][:19]}{RESET}  "
                      f"PID {event['pid']} ({event['process']}) sonlandırıldı")

        # Servis Restart Döngüleri
        restarts = self.service_restart_analysis()
        if restarts:
            print(f"\n  {BOLD}🔄 Servis Restart Sayıları{RESET}")
            print(f"  {'─' * 40}")
            for service, cnt in list(restarts.items())[:8]:
                color = DKRED if cnt >= 10 else (RED if cnt >= 5 else ORANGE)
                print(f"  {color}{service:<35}{RESET}  {cnt:>4}x")

        # Saatlik Dağılım
        if verbose:
            hourly = self.hourly_distribution()
            if hourly:
                print(f"\n  {BOLD}⏰ Saatlik Aktivite{RESET}")
                print(f"  {'─' * 50}")
                max_h = max(hourly.values(), default=1)
                for hour, count in sorted(hourly.items()):
                    bar_len = int(count / max_h * 28)
                    bar     = "█" * bar_len + "░" * (28 - bar_len)
                    c       = DKRED if bar_len > 22 else (RED if bar_len > 15 else CYAN)
                    print(f"  {hour}  {c}{bar}{RESET}  {count}")

        print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}\n")

    def to_dict(self) -> dict:
        self._ensure_parsed()
        score, score_desc = self.system_health_score()
        return {
            "file":             self.log_path,
            "total_entries":    len(self._entries),
            "system_health":    score,
            "health_status":    score_desc,
            "anomaly_distribution": self.anomaly_distribution(),
            "auth_analysis":    self.auth_failure_analysis(),
            "oom_events":       self.oom_events(),
            "service_restarts": self.service_restart_analysis(),
            "hourly_activity":  self.hourly_distribution(),
            "critical_events":  [
                {"timestamp": e.timestamp.isoformat() if e.timestamp else "?",
                 "process": e.process, "message": e.message[:100],
                 "anomaly": e.anomaly_type}
                for e in self.critical_events()
            ],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Örnek Log Üretici
# ─────────────────────────────────────────────────────────────────────────────

def generate_sample_syslog(path: str = "sample_syslog.log", lines: int = 400) -> None:
    """Test için örnek syslog üretir."""
    import random

    TEMPLATES = [
        ("sshd",     "Failed password for root from 185.220.101.35 port 54321 ssh2"),
        ("sshd",     "Failed password for invalid user admin from 218.92.0.198 port 12345 ssh2"),
        ("sshd",     "Accepted publickey for deploy from 10.0.0.5 port 43210 ssh2"),
        ("kernel",   "Out of memory: Killed process 12345 (apache2) total-vm:2048000kB"),
        ("kernel",   "EXT4-fs error (device sda1): ext4_find_entry: reading directory lblock 0"),
        ("kernel",   "kernel: [12345.678] BUG: unable to handle kernel NULL pointer dereference"),
        ("systemd",  "nginx.service: start request repeated too quickly, refusing to start"),
        ("systemd",  "apache2.service: Main process exited, code=killed, status=9/KILL"),
        ("CRON",     "pam_unix(cron:session): session opened for user root by (uid=0)"),
        ("sudo",     "root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"),
        ("ntpd",     "time slew -0.123456789s"),
        ("dhclient", "bound to 192.168.1.100 -- renewal in 43200 seconds"),
        ("rsyslogd", "start, version 8.2102.0"),
        ("useradd",  "new user: name=hacker, UID=1337, GID=1337, home=/home/hacker"),
        ("ufw",      "BLOCK] IN=eth0 OUT= MAC=... SRC=185.220.101.35 DST=10.0.0.1 PROTO=TCP DPT=22"),
    ]

    MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    now = datetime.now()

    with open(path, "w", encoding="utf-8") as f:
        for i in range(lines):
            ts       = now - timedelta(seconds=random.randint(0, 86400))
            month    = MONTHS[ts.month - 1]
            day      = ts.day
            time_str = ts.strftime("%H:%M:%S")
            proc, msg = random.choice(TEMPLATES)
            pid      = random.randint(1000, 65535)
            host     = "ubuntu-server"
            f.write(f"{month} {day:2d} {time_str} {host} {proc}[{pid}]: {msg}\n")

    print(f"  ✅ Örnek syslog oluşturuldu: {path} ({lines} satır)")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, json

    parser = argparse.ArgumentParser(
        description="Syslog Anomaly Detector",
        epilog="""
Örnekler:
  python syslog_analyzer.py /var/log/syslog
  python syslog_analyzer.py /var/log/auth.log --json
  python syslog_analyzer.py --generate-sample
        """
    )
    parser.add_argument("logfile",           nargs="?")
    parser.add_argument("--json",            action="store_true")
    parser.add_argument("--quiet",           action="store_true")
    parser.add_argument("--generate-sample", action="store_true")
    parser.add_argument("--sample-lines",    type=int, default=500)
    args = parser.parse_args()

    if args.generate_sample:
        generate_sample_syslog("sample_syslog.log", args.sample_lines)
        args.logfile = "sample_syslog.log"

    if not args.logfile:
        parser.print_help()
        sys.exit(1)

    analyzer = SyslogAnalyzer(args.logfile)
    analyzer.parse()

    if args.json:
        print(json.dumps(analyzer.to_dict(), indent=2, ensure_ascii=False, default=str))
    else:
        analyzer.print_report(verbose=not args.quiet)
