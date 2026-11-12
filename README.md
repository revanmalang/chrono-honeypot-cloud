# Chrono-Honeypot Cloud

**Serverless Polymorphic Deception Engine** — honeypot aktif berbasis Python (hanya *standard library*) yang berjalan di Vercel Serverless Functions.

Tool ini menyamar sebagai aplikasi web/API produksi yang rentan, lalu **memutasi respons secara real-time** sesuai teknik serangan dan tingkat keahlian penyerang, memperlambat bot otomatis (tarpit), dan mengekspor setiap interaksi sebagai log JSON berlabel **MITRE ATT&CK** ke stdout (Vercel Logs) dan webhook (Discord / Slack / SIEM).

> **Hanya untuk pertahanan.** Deploy di akun/infrastruktur milik sendiri, uji hanya ke deployment sendiri. Tidak ada kode yang mengeksekusi, mengambil, atau menyimpan input penyerang; semua respons adalah data sintetis dan semua nilai yang dipantulkan di-*escape*.

---

## 1. Cara kerja

```
Request liar (/.env, /wp-login.php, /api/v1/users, ?id=1' OR 1=1 ...)
        │   vercel.json: rewrite "/(.*)" → /api/index
        ▼
┌─────────────────────────── api/index.py (satu invokasi, stateless) ───────────────────────────┐
│ 1. RequestContext     parse URL/header/JSON/form, decode berlapis, sidik jari (HMAC IP+UA)    │
│ 2. BehavioralProfiler skill  : automated_scanner | script_kiddie | advanced_persistent_threat  │
│                       intent : sqli, lfi, credential stuffing, api exploitation, rce, ssrf... │
│ 3. DeceptionEngine    pilih "persona" stack (Apache/PHP, Express, Django, IIS, Tomcat) lalu    │
│                       mutasi respons: .env palsu + honey-token, error/dump SQL palsu, dll.     │
│ 4. AdaptiveTarpit     delay berdasarkan skill, dijepit di dalam budget waktu fungsi            │
│ 5. ThreatIntelExporter log JSON (MITRE ATT&CK) → stdout + webhook paralel                      │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

### "Chrono" dan "stateless" — bagaimana konsisten tanpa database?

Semua data umpan dibuat dari **RNG deterministik**: `HMAC(HONEYPOT_SECRET, fingerprint | epoch | tujuan)`.

- **Fingerprint** = HMAC dari `IP + User-Agent` → penyerang yang sama selalu melihat persona dan data umpan yang sama (tampak konsisten).
- **Epoch** = `waktu / MUTATION_WINDOW_SECONDS` (default 1 jam) → setiap jendela waktu, *stack* palsu bermutasi (mis. dari Apache/PHP menjadi Express/PostgreSQL). Ini mempersulit fingerprinting jangka panjang. Set `0` untuk persona tetap.
- **Honey-token bertanda tangan**: API key umpan berformat `nlr_live_<fp8><acak><sig>`. Jika token itu muncul lagi di request berikutnya, engine memverifikasi tanda tangannya dan mencatat `honey_token_reuse` (severity **critical**) beserta fingerprint yang memanennya — tanpa menyimpan apa pun.

---

## 2. Struktur proyek

```
chrono-honeypot-cloud/
├── api/
│   └── index.py        # seluruh engine (handler Vercel: class `handler`)
├── vercel.json         # rewrite semua path ke engine + maxDuration
├── requirements.txt    # kosong (hanya komentar) — tanpa dependensi
├── .gitignore
└── README.md
```

`vercel.json` memakai satu aturan `rewrites` `"/(.*)" → "/api/index"`. Jadi **semua** path (`/admin`, `/.env`, `/wp-login.php`, `/api/v1/users`, path acak apa pun) masuk ke engine, bukan hanya daftar tetap.

---

## 3. Environment Variables

| Variabel | Default | Fungsi |
|---|---|---|
| `HONEYPOT_SECRET` | *(wajib, ≥ 16 karakter)* | Kunci HMAC untuk fingerprint, data umpan, dan tanda tangan honey-token. Buat: `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Mengganti nilainya membuat token lama tidak lagi dikenali. |
| `DISCORD_WEBHOOK_URL` | – | URL webhook Discord (embed). |
| `SLACK_WEBHOOK_URL` | – | URL Incoming Webhook Slack. |
| `SIEM_WEBHOOK_URL` | – | Endpoint HTTP(S) yang menerima JSON (Splunk HEC, Elastic, Wazuh, n8n, dll.). |
| `SIEM_AUTH_HEADER` | – | Nilai header `Authorization` untuk SIEM, mis. `Bearer xxx` atau `Splunk xxx`. |
| `SIEM_HMAC_SECRET` | – | Jika diisi, body ditandatangani dan dikirim di header `X-Chrono-Signature: sha256=<hex>`. |
| `SIEM_FORMAT` | `json` | `json` (event apa adanya) atau `splunk-hec` (dibungkus `{"event": ...}`). |
| `WEBHOOK_MIN_SEVERITY` | `medium` | Batas severity minimum untuk Discord/Slack: `info`, `low`, `medium`, `high`, `critical`. |
| `SIEM_MIN_SEVERITY` | `low` | Batas severity minimum untuk SIEM. |
| `TARPIT_ENABLED` | `true` | Aktif/nonaktifkan tarpit. |
| `TARPIT_MAX_SECONDS` | `4.0` | Delay maksimum tarpit (0–8). Scanner mendapat delay penuh, APT hanya ±10% agar tidak curiga. |
| `FUNCTION_BUDGET_SECONDS` | `8.0` | Anggaran waktu total per request. **Harus lebih kecil dari `maxDuration` di `vercel.json` (10).** Delay dijepit otomatis agar tidak terjadi 504. |
| `WEBHOOK_TIMEOUT_SECONDS` | `2.0` | Timeout pengiriman webhook (webhook dikirim paralel dengan tarpit). |
| `MUTATION_WINDOW_SECONDS` | `3600` | Lama satu epoch mutasi persona. `0` = persona tetap. |
| `DECOY_ORG` | `Aurora Logistics` | Nama perusahaan fiktif di halaman/data umpan. **Jangan pakai merek asli.** |
| `LOG_CLEARTEXT_CREDENTIALS` | `false` | Default: password yang dicoba **tidak** dicatat (hanya panjang + 12 hex pertama SHA-256). Kredensial credential-stuffing sering milik korban asli, jadi biarkan `false` kecuali ada alasan kuat. |
| `CANARY_AWS_ACCESS_KEY_ID` / `CANARY_AWS_SECRET_ACCESS_KEY` | – | Pasangan AWS canary dari <https://canarytokens.org> (jenis *AWS keys*). Jika diisi, dipakai di `.env`, `/proc/self/environ`, metadata SSRF, dll. Saat penyerang mencoba memakainya, Anda diberi tahu **di luar** honeypot. |
| `SENSOR_ID` | `chrono-<env>-<region>` | Label sensor di log. |
| `MAX_BODY_BYTES` | `65536` | Batas body yang dibaca per request. |

### Membuat webhook

- **Discord:** Server Settings → Integrations → Webhooks → *New Webhook* → pilih channel → *Copy Webhook URL*.
- **Slack:** <https://api.slack.com/apps> → *Create New App* → *Incoming Webhooks* → *Activate* → *Add New Webhook to Workspace* → salin URL.
- **SIEM / koleksi log:** endpoint HTTPS apa pun yang menerima `POST application/json`. Untuk uji coba cepat, <https://webhook.site> cukup.

Pesan chat selalu mengirim `allowed_mentions: {"parse": []}` (tidak ada `@everyone` dari input penyerang) dan semua teks penyerang dipotong serta di-*escape*.

---

## 4. Menguji dengan aman

**Aturan:** hanya uji ke deployment milik Anda sendiri atau `127.0.0.1`. Jangan arahkan sqlmap/nikto/dirb ke sistem pihak lain.

### A. Lokal (hanya loopback)

```bash
# macOS/Linux/Git Bash
export HONEYPOT_SECRET="ganti-dengan-secret-acak-panjang"
export TARPIT_MAX_SECONDS=0.5
python api/index.py            # http://127.0.0.1:8000
```

```powershell
# Windows PowerShell
$env:HONEYPOT_SECRET="ganti-dengan-secret-acak-panjang"
$env:TARPIT_MAX_SECONDS="0.5"
python api/index.py
```

### B. Skenario uji (ganti `BASE`; di Windows pakai Git Bash/WSL atau `curl.exe`)

```bash
BASE=http://127.0.0.1:8000          # atau https://nama-proyek.vercel.app

curl -i  "$BASE/"                                                           # halaman portal (severity info, tidak dikirim webhook)
curl -i  "$BASE/.env"                                                       # .env palsu + honey-token
curl -s --path-as-is "$BASE/download?file=../../../../.env"                 # path traversal -> .env palsu
curl -s  "$BASE/view?f=%252e%252e%252f%252e%252e%252fetc%252fpasswd"        # double-encoding -> passwd palsu
curl -s  "$BASE/search?q=1'%20UNION%20SELECT%20username,password%20FROM%20users--"   # dump tabel palsu
curl -s  "$BASE/page?id=5'--"                                               # error SQL sesuai database persona
curl -s -w "%{time_total}s\n" -o /dev/null "$BASE/item?id=1;SELECT%20pg_sleep(3)--"  # blind SQLi "berhasil" (~3 dtk)
curl -s -X POST "$BASE/wp-login.php" -d "log=admin&pwd=test123"             # login WordPress palsu
curl -s -X POST "$BASE/api/v1/login" -H "Content-Type: application/json" \
     -d '{"email":"user@example.com","password":"Passw0rd!"}'               # credential stuffing
curl -s  "$BASE/api/v1/users"                                               # daftar user palsu (+ API key umpan)
curl -s -X POST "$BASE/api/v1/users" -H "Content-Type: application/json" \
     -d '{"name":"x","isAdmin":true}'                                       # mass assignment
curl -s  "$BASE/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role"  # SSRF -> kredensial metadata palsu
curl -s  "$BASE/ping?host=127.0.0.1;id"                                     # RCE palsu -> uid=33(www-data)
curl -s -o /dev/null -w "%{time_total}s\n" -A "sqlmap/1.7.2" "$BASE/admin"  # terdeteksi scanner + tarpit
```

Uji **honey-token reuse**: ambil nilai `INTERNAL_API_TOKEN` dari `/.env`, lalu kirim `curl -H "X-API-Key: <token>" "$BASE/api/v1/anything"` — event `honey_token_reuse` (critical) harus muncul.

### C. Smoke test pertama setelah deploy ke Vercel

Buka `https://nama-proyek.vercel.app/wp-login.php`. Jika Anda melihat halaman login WordPress palsu, rewrite dan handler bekerja. Lalu cek log (lihat bawah). Jika Anda melihat halaman 404 Vercel/“NOT_FOUND”, periksa bahwa `vercel.json` ada di root repo dan folder `api/` terunggah.

### D. Melihat log

- Dashboard Vercel → proyek → **Logs** (Runtime Logs), cari `chrono-honeypot/1.0`.
- CLI: `vercel logs <url-deployment>`.
- Retensi log runtime Vercel singkat dan bergantung plan; itu sebabnya webhook/SIEM ada. Untuk arsip jangka panjang gunakan Log Drains atau SIEM Anda.

Contoh event (dipersingkat):

```json
{
  "schema": "chrono-honeypot/1.0",
  "@timestamp": "2026-11-12T12:10:23.434Z",
  "event_id": "e7fca910-f419-4047-8715-fb833354e119",
  "sensor": {"id": "chrono-production-sin1", "region": "sin1", "commit": "a1b2c3d"},
  "source": {"ip": "203.0.113.7", "fingerprint": "963d1eaca5318847", "geo": {"country": "ID"}},
  "http": {"method": "GET", "path": "/download", "user_agent": "curl/8.5.0",
           "parameters": {"query": {"file": "../../../../.env"}, "body": {}}},
  "classification": {
    "skill_level": "script_kiddie", "confidence": 0.66,
    "primary_intent": "path_traversal_lfi", "intents": ["path_traversal_lfi", "reconnaissance"],
    "severity": "medium", "evasion": [],
    "evidence": [{"intent": "path_traversal_lfi", "technique": "directory_traversal", "severity": "high", "match": "../../../../"}]
  },
  "mitre_attack": {"matrix": "enterprise", "techniques": [
    {"tactic_id": "TA0001", "tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"},
    {"tactic_id": "TA0007", "tactic": "Discovery", "technique_id": "T1083", "technique_name": "File and Directory Discovery"}]},
  "deception": {"persona": "iis-aspnet-mssql", "mutation_epoch": 498468, "decoy_type": "fake_file:env",
                "response_status": 200, "honey_trace": "963d1eac", "tarpit_delay_ms": 456}
}
```

Header `Authorization` dan `Cookie` selalu disensor; field password disensor kecuali `LOG_CLEARTEXT_CREDENTIALS=true`.

---

## 5. Operasional dan hardening

1. **Pisahkan proyek.** Gunakan proyek Vercel (dan idealnya akun/tim) khusus honeypot. Jangan simpan secret produksi apa pun di environment-nya selain webhook.
2. **Biaya dan kuota.** Tarpit menahan fungsi tetap berjalan selama delay. Scanner agresif bisa membuat ribuan invokasi × beberapa detik. Pantau **Usage**; turunkan `TARPIT_MAX_SECONDS` atau set `TARPIT_ENABLED=false` bila perlu. Di Vercel Firewall, pasang aturan *rate limit* sesuai plan Anda agar satu IP tidak menghabiskan kuota.
3. **Banjir webhook.** Naikkan `WEBHOOK_MIN_SEVERITY` (mis. `high`) untuk chat; biarkan volume penuh masuk ke SIEM. Kunjungan biasa ke `/` bersifat `info` dan tidak dikirim ke webhook.
4. **Risiko dianggap phishing.** Halaman login palsu dapat memicu deteksi otomatis (Google Safe Browsing, sistem abuse hosting). Gunakan organisasi fiktif (`DECOY_ORG`), jangan meniru merek nyata, jangan sebarkan URL-nya, dan siapkan kemungkinan proyek ditandai.
5. **Privasi.** Alamat IP adalah data pribadi di banyak yurisdiksi (UU PDP No. 27/2022, GDPR). Tentukan masa retensi log dan jangan aktifkan `LOG_CLEARTEXT_CREDENTIALS` tanpa dasar yang jelas.
6. **Canary token.** Pasang kunci AWS canary (`CANARY_AWS_*`) agar penggunaan kredensial umpan di dunia nyata memicu alert dari layanan canary.
7. **Rotasi secret.** Mengganti `HONEYPOT_SECRET` mengubah semua fingerprint dan membuat honey-token lama tidak terverifikasi lagi.

---

## 8. Batasan (jujur)

- **Stateless.** "Profil" penyerang dihitung per request. Korelasi lintas request dilakukan lewat `fingerprint` di SIEM Anda, bukan di dalam fungsi.
- **Persona tidak sempurna.** Edge Vercel menambahkan header sendiri (mis. `x-vercel-id`, dan dapat menimpa `Server`) yang tidak bisa dihapus. Penyerang mahir bisa mengenali Vercel; mutasi stack meyakinkan untuk scanner dan script, bukan jaminan terhadap APT.
- **Normalisasi path.** Klien dan edge sering menormalkan `/../`. Path traversal biasanya tiba lewat query/body atau dalam bentuk ter-encode, dan itu yang dideteksi.
- **Deteksi berbasis heuristik** (regex + skor), bukan WAF. Bisa ada false positive/negative; jangan dipakai untuk memblokir trafik sah.
- **Hanya HTTP(S).** Tidak mencakup SSH/SMB/dll.
- Engine **tidak pernah** mengeksekusi payload, membuka URL dari input (SSRF hanya disimulasikan), atau menghubungi callback seperti `${jndi:...}`; domain callback tercatat sebagai bukti.

---

## 6. Kustomisasi

| Ingin… | Ubah di `api/index.py` |
|---|---|
| Menambah signature serangan | tuple `SIGNATURES` (`_sig(...)` dengan intent, severity, ID MITRE) |
| Menambah teknik ke katalog MITRE | dict `MITRE_CATALOG` |
| Menambah persona stack | tuple `PERSONAS` (+ template error di `_sql_error` / `_not_found`) |
| Menambah file/lure palsu | `FILE_TARGETS`, lalu builder `_f_*` dan peta `builders` di `_serve_file` |
| Menambah route umpan | `DeceptionEngine._route` |
| Mengubah agresivitas tarpit | `AdaptiveTarpit.FACTORS` atau env `TARPIT_MAX_SECONDS` |
| Menambah tujuan webhook | `ThreatIntelExporter.dispatch` + builder payload |

Kompatibel dengan Python 3.9+ (Vercel memakai versi lebih baru secara default).
