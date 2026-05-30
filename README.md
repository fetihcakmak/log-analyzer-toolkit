# 📋 Log Analyzer Toolkit

> Tek araç ile Apache access.log, Nginx error.log ve Syslog analizini yapan kapsamlı bir güvenlik ve sistem izleme aracı.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Stdlib](https://img.shields.io/badge/Dep-Stdlib_Only-success)](.)
[![Formats](https://img.shields.io/badge/Formats-3_Destekli-orange)](.)
[![Status](https://img.shields.io/badge/Status-Active-success)](.)

---

## 📌 Proje Hakkında

3 farklı log formatını otomatik olarak tespit edip analiz eden tek bir araç.

**Commit Geçmişi:**
| Commit | Açıklama |
|--------|----------|
| `apache access log analyzer` | Trafik, bot, hata analizi |
| `nginx error log analyzer` | Upstream, spike, sağlık skoru |
| `syslog anomaly detector` | Kernel, OOM, auth, cron |

---

## 🧠 Mimari

```
main.py
  │
  ├── 🌐 apache_analyzer.py    ← Combined Log Format
  │     • HTTP status dağılımı
  │     • Bot vs insan trafiği
  │     • Saatlik heatmap
  │     • SQLi / 404 crawler tespiti
  │
  ├── 🔴 nginx_analyzer.py     ← Nginx Error Format
  │     • Hata seviyesi dağılımı
  │     • Upstream sorunları
  │     • Spike tespiti
  │     • Servis sağlık skoru
  │
  └── 🖥  syslog_analyzer.py   ← RFC 3164 / RFC 5424
        • Kernel panic / OOM killer
        • Auth failure (SSH brute)
        • Servis restart döngüleri
        • Cron anomalileri
```

---

## 🚀 Kurulum

```bash
git clone https://github.com/fetihcakmak/log-analyzer-toolkit.git
cd log-analyzer-toolkit

# Sadece Python standart kütüphanesi gerekli — pip kurulumu gerekmez!
python main.py --demo
```

---

## ⚡ Kullanım

### Hızlı Demo (Örnek Loglar İle)
```bash
python main.py --demo
```

### Otomatik Tespit
```bash
python main.py access.log              # Apache olarak tespit eder
python main.py error.log               # Nginx olarak tespit eder  
python main.py /var/log/syslog         # Syslog olarak tespit eder
```

### Manuel Tip Belirtme
```bash
python main.py mylog.log --type apache
python main.py myerrors.log --type nginx
python main.py mylog.log --type syslog
```

### Birden Fazla Dosya
```bash
python main.py *.log --type auto
python main.py /var/log/apache2/*.log --type apache
```

### JSON Çıktı
```bash
python main.py access.log --json
python main.py access.log --json --output report.json
```

### Bireysel Modüller
```bash
# Apache Analyzer
python apache_analyzer.py /var/log/apache2/access.log
python apache_analyzer.py --generate-sample --sample-lines 2000

# Nginx Analyzer
python nginx_analyzer.py /var/log/nginx/error.log
python nginx_analyzer.py --generate-sample

# Syslog Analyzer
python syslog_analyzer.py /var/log/syslog
python syslog_analyzer.py --generate-sample
```

---

## 🌐 Apache Access Log Analizi

```
╔══════════════════════════════════════════════════════╗
║           🌐 APACHE ACCESS LOG ANALİZİ              ║
╚══════════════════════════════════════════════════════╝

  📊 Genel İstatistikler
  Toplam İstek    :     15,234
  Benzersiz IP    :        847
  İnsan Trafiği   :     11,892
  Bot Trafiği     :      3,342  (21.9%)
  Hata Oranı      :       4.2%

  📋 HTTP Status Dağılımı
  2xx  ████████████████████████  13,891  (91.2%)
  3xx  ██                           421   (2.8%)
  4xx  ████                         789   (5.2%)
  5xx  ▌                            133   (0.9%)

  🔗 En Çok Ziyaret Edilen URL'ler
   1. /                              4,521
   2. /api/v1/users                  2,108
   3. /static/app.js                 1,893
   ...

  🚨 Şüpheli IP'ler (SQLi + 403/404 yağmuru)
  185.220.101.35    403:127  404:445  SQLi:3
```

---

## 🔴 Nginx Error Log Analizi

```
  Servis Sağlık Skoru: 71/100  🟡 İyi

  🔎 Hata Seviyesi Dağılımı
  warn     ███████████████████████   1,234
  error    ████████████████          891
  crit     ██                        45

  📂 Hata Kategorisi
  upstream_timeout         ───────── 234
  upstream_failed          ─────     189
  file_not_found           ───       87
  ssl_error                ──        43

  ⚡ Hata Spike'ları (5 dakikalık pencere)
  2024-01-15 03:45  ████ 87 hata  (en kötü: error)
```

---

## 🖥 Syslog Anomali Tespiti

```
  Sistem Sağlık Skoru: 45/100  🟠 Orta

  🔍 Tespit Edilen Anomaliler
  💀 kernel_panic         █████████            3
  🔴 oom_killer           ████████████████    12
  🔐 auth_failure         ████████████████████████████ 289
  🔄 service_restart      ██████████          8

  🚨 KRİTİK OLAYLAR (3 adet)
  01-15 03:22:41  kernel   Out of memory: Killed process 12345 (apache2)
  01-15 04:11:15  kernel   BUG: unable to handle kernel NULL pointer
```

---

## 📁 Dosya Yapısı

```
log-analyzer-toolkit/
├── main.py              ← Ana giriş noktası (otomatik tespit + multi-file)
├── apache_analyzer.py   ← Apache access.log analizi (Commit 1)
├── nginx_analyzer.py    ← Nginx error.log analizi (Commit 2)
├── syslog_analyzer.py   ← Syslog anomali tespiti (Commit 3)
└── requirements.txt     ← Standart kütüphane (kurulum gerekmez)
```

---

## 🔗 İlgili Projeler

- [network-anomaly-detector](../network-anomaly-detector) — Ağ trafik anomali tespiti
- [ssh-brute-force-detector](../ssh-brute-force-detector) — SSH saldırı tespiti + Geo
- [port-scanner-from-scratch](../port-scanner-from-scratch) — Port tarama + Servis versiyonu

---

*Fetih Çakmak — Cybersecurity Portfolio*
