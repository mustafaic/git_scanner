# THREAT_MODEL.md

master_prompt.md 5'in belirttiği saldırgan modelleri üzerinden yazılmıştır.
Her madde: varlık/tehdit → mevcut kontroller (kod referanslı) → kalan risk.

## Varlıklar

- **Kod/bağımlılık envanteri** (repo listesi, lockfile içerikleri, bileşen
  adları/sürümleri) — şirketin saldırı yüzeyinin haritası, dışarı çıkarsa
  hedefli saldırı planlamasını kolaylaştırır.
- **Secret bulguları** (kural ID, dosya, hash) — ham değer hiçbir yerde
  tutulmaz, ama "nerede bir secret var" bilgisinin kendisi değerlidir.
- **GitHub App private key** — tüm organizasyon reposuna okuma erişimi
  verir.
- **Kullanıcı hesapları** (parola hash'leri, API token hash'leri) ve audit
  log.
- **Şifreli yedekler** — tüm yukarıdakilerin tarihsel kopyası.

## Saldırgan modelleri

### 1. Kötü niyetli repo içeriği (worker'a verilen güvenilmeyen girdi)

Taranan repo'nun kendisi (lockfile, kod) kötü niyetli olabilir (ör. XSS
payload'lı paket adı, path traversal'lı dosya yolu, komut enjeksiyonu
hedefleyen paket adı).

**Kontroller:**
- Worker **hiçbir repo kodu çalıştırmaz** — sadece statik parse/scan
  (`worker/main.py`, `adapters/osv_scanner.py`, `adapters/gitleaks.py`).
- Panel **hiçbir yerde kopyala-yapıştır kurulum komutu üretmez**
  (2026-11-11, kullanıcı kararı): komut ipucu gösteren tek yer olan A1
  Aksiyon Grupları sayfası ve onu besleyen `build_install_hint` /
  `is_safe_package_name` / `is_safe_version_string` fonksiyonları
  `core/lockfile_parser.py`'den tamamen kaldırıldı. Böylece "paket adı
  (`lodash; rm -rf /`) kullanıcının terminaline sızar" saldırı sınıfı
  ortadan kalktı — artık doğrulanacak bir komut üretimi yok.
- Jinja2 otomatik HTML escape (varsayılan, `|safe` kullanılmıyor) — XSS
  payload'lı paket adı HTML'de düz metin olarak görünür.
- Parametreli SQL (SQLAlchemy ORM/Core, hiçbir yerde string-interpolasyonlu
  SQL yok).

**Kalan risk:** Paket adı/sürüm hâlâ panelde METİN olarak gösterilir (bulgu
listeleri, detay sayfası) — buradaki savunma tek başına Jinja2 escape'idir.
Kullanıcı bu metni kendi isteğiyle kopyalayıp bir terminale yapıştırırsa
sistemin uyarabileceği bir nokta yok; eskiden bu senaryo için ekosistem
grameri doğrulaması vardı, komut ipucu özelliği kaldırıldığı için bu
doğrulama katmanı da kaldırıldı.

### 2. Symlink / zip-bomb tuzakları

Kötü niyetli bir lockfile veya repo yapısı, worker'ı disk/bellek
tükenmesine zorlamaya veya dosya sistemi dışına (`/run/secrets/...`)
symlink ile çıkmaya çalışabilir.

**Kontroller:**
- Worker `read_only: true`, `network_mode: none`, `cap_drop: [ALL]`,
  `no-new-privileges`, non-root, `tmpfs /tmp` (`deploy/docker-compose.yml`).
- Blob boyutu sınırlı (`MAX_LOCKFILE_BLOB_BYTES`, `orchestrator/extraction.py`)
  — aşırı büyük lockfile indirilmeden reddedilir.
- GitHub Blobs API zaten 100MB blob sınırı koyar (VERIFIED_FACTS.md).

**Kalan risk:** Gerçek bir symlink-tuzağı/zip-bomb fixture'ıyla ampirik
test yapılmadı (worker'ın ağsız çalıştığı, VERIFIED_FACTS.md madde 9'da
gerçek container ile doğrulandı, ama bu spesifik saldırı sınıfı ayrıca
test edilmedi).

### 3. Çalınmış token/key

GitHub App private key, API token'lar, oturum çerezleri veya SMTP/backup
şifreleme anahtarları çalınırsa.

**Kontroller:**
- GitHub App private key SADECE orchestrator'da, Docker secret (0400
  benzeri salt-okunur mount), `register_secret()` ile log maskeleme
  (`orchestrator/github_auth.py`). Worker ve app bu key'i HİÇ görmez.
- API token'lar SHA-256 hash'lenmiş saklanır (`core/auth.py::hash_api_token`),
  ham değer SADECE oluşturma anında gösterilir.
- Oturum çerezi HttpOnly+Secure(prod)+SameSite=Lax, DB-destekli (admin
  "oturumu zorla kapat" yapabilir — `revoke_session`), boşta 30 dk zaman
  aşımı (`app/auth_service.py`).
- Backup şifreleme anahtarı Docker secret dosyası, DB/env'de düz metin
  YOK (`core/backup_crypto.py`).

**Kalan risk:** TOTP kaldırıldığı için (ASSUMPTIONS.md #14) çalınan bir
parola artık TEK başına yeterli — ikinci faktör yok. Bu, kullanıcının
açık kararıyla kabul edilen bir risk artışıdır.

### 4. Ele geçirilmiş worker + zehirlenmiş sonuç

Worker container'ı (veya scanner binary'si) ele geçirilip sahte/zehirli
bir tarama sonucu üretirse.

**Kontroller:**
- Worker **ağsız** (`network_mode: none`) — ele geçirilse bile dışarı veri
  sızdıramaz (VERIFIED_FACTS.md madde 9: gerçek container'da `OSError:
  Network is unreachable` doğrulandı).
- Scanner çıktısı GÜVENİLMEYEN girdi sayılır: şema doğrulaması
  (`adapters/osv_scanner.py::parse`, `adapters/gitleaks.py::parse` —
  gecersiz JSON'da `ValueError`), sanity-gate (bileşen sayısında ani çöküş
  → `needs_review`, `orchestrator/extraction.py::COLLAPSE_RATIO_THRESHOLD`).
- RESOLVED kuralı: hata/timeout/eksik lockfile/bayat DB/sanity-gate
  uyarısında HİÇBİR bulgu kapanmaz (`core/finding_model.py::ingest_lockfile_findings`).

**Kalan risk:** Worker container imajının kendisi (binary'ler, Python
paketleri) tedarik zinciri saldırısına karşı SBOM/imza doğrulaması ile
korunmuyor (bkz. LIMITATIONS.md madde "kendi tedarik zincirimiz" henüz
tam uygulanmadı — sadece sürüm pinleme var).

### 5. İçeriden kullanıcı (ele geçirilmiş veya kötü niyetli viewer/admin)

**Kontroller:**
- RBAC SUNUCU TARAFINDA zorlanır (her route `require_user`/`require_admin`
  dependency'si, UI gizleme değil) — `app/deps.py`.
- Viewer HİÇBİR yazma uç noktasına erişemez (TEK istisna: kendi read-only
  API token'ı — ASSUMPTIONS.md #11, `tests/integration/test_app_panel_postgres.py::test_viewer_can_only_reach_own_token_write_endpoints_all_other_writes_blocked`).
- Her durum değişikliği/suppression/kullanıcı-rol-ayar/export audit
  log'a yazılır (`app/auth_service.py::record_audit`), append-only.
- Suppression/FP/ACCEPTED_RISK SADECE admin + zorunlu gerekçe.

**Kalan risk:** Admin sayısı az tutulmalı (operasyonel kontrol, kodla
zorlanamaz) — RUNBOOK.md'de belgelenir. Audit log'un kendisi SİLİNEMEZ bir
UI'dan korunmuyor (DB seviyesinde hiçbir DELETE endpoint'i yok, ama
doğrudan DB erişimi olan biri audit log'u değiştirebilir — bu, DB'ye
erişimin kendisinin ayrı bir güven sınırı olduğunu gösterir).

### 6. Zehirlenmiş advisory/mirror

CISA KEV, EPSS veya OSV-Scanner offline DB mirror'ı yanlış/zehirli veri
içerirse (ör. gerçek bir zafiyeti "withdrawn" göstermek).

**Kontroller:**
- Mirror sync HER ZAMAN resmi kaynaktan toplu indirme (yön: içeri), hiçbir
  "paket bazlı sorgu" yapılmaz (`orchestrator/mirror.py`).
- `advisory_mirror_syncs` tablosu her senkronun zaman damgası/checksum'ını
  tutar; bulgu KAPATMA kararı DB tazeliğine bağlıdır
  (`is_advisory_data_fresh`, `ADVISORY_MAX_AGE_SECONDS`).
- Checksum doğrulaması indirme anında yapılır.

**Kalan risk:** Mirror kaynaklarının (cisagov/kev-data GitHub mirror'ı,
first.org EPSS, Google'ın OSV GCS bucket'ı) KENDİLERİ ele geçirilirse
(tedarik zinciri saldırısı) bu seviye korunmuyor — bu, bu projenin kontrol
alanının dışında (resmi kaynakların kendi güvenliği).

### 7. Veri sızdırma: egress

Repo içeriği/paket adı/bulgu/secret bilgisinin bilerek veya kazayla
dışarı çıkması.

**Kontroller:** bkz. `docs/EGRESS_REPORT.md` (ayrı belge) — worker ağsız,
OSV-Scanner HER ZAMAN `--offline`, Gitleaks ağ çağrısı yapmıyor (ampirik +
VERIFIED_FACTS.md), Teams webhook (uygulanmadıysa zaten devre dışı; varsa
`minimal` içerik).

**Kalan risk:** Orchestrator'ın kendisi hâlâ doğrudan internete çıkıyor
(egress-proxy henüz yok — `deploy/docker-compose.yml` üst yorum: "Asama
3+ kapsami"). Host/ağ güvenlik duvarında varsayılan-engelle egress kuralı
ÖNERİLİR ama bu depo tarafından UYGULANMAZ (ops ekibinin sorumluluğu).

### 8. Scanner telemetrisi / çevrimiçi sorgular

OSV-Scanner veya Gitleaks'in kendi varsayılan ağ davranışı.

**Kontroller:** VERIFIED_FACTS.md madde 6 (OSV-Scanner KRİTİK bulgu:
varsayılan ÇEVRİMİÇİ, `--offline` + önceden indirilmiş DB ZORUNLU) ve
madde 2 (Gitleaks için COULD_NOT_VERIFY, dolaylı kanıt + worker'ın ağsız
olması ikinci güvence).

**Kalan risk:** `--download-offline-databases` adımı (orchestrator'ın
mirror sync'i) her gün gerçek ağ çıkışı yapıyor — bu KASITLI (herkese açık
veri indirme, egress politikasının (b) maddesi) ama allowlist'in doğru
kapsamda tutulması operasyonel bir sorumluluktur.

### 9. Bulut bildirim kanalları (Teams)

Uygulandı (2026-11-09, LIMITATIONS.md madde 3). Webhook URL'si admin
panelden (`/settings`) girilir, Fernet ile şifrelenip DB'de saklanır
(`TEAMS_ENCRYPTION_KEY_PATH` — SMTP host'un aksine env'de değil, kullanıcı
kararı: panelden kolayca değiştirilebilir olmalı). İçerik HER ZAMAN minimal
(sayılar + panel linki) — `core.notifications.build_minimal_teams_text`
finding/secret nesnesini parametre olarak bile almaz, bu yüzden
repo/paket/CVE/secret detayının yanlışlıkla sızması yapısal olarak
engellenir (bkz. `tests/unit/test_notifications.py`).

**SSRF kontrolü:** sunucu admin'in girdiği URL'ye POST atar (admin zaten
güvenilir bir rol, ama webhook URL'si host-allowlist'e tabi: sadece
`*.webhook.office.com`/`*.logic.azure.com` kabul edilir — ele geçirilmiş
bir admin hesabının sunucuyu iç ağa yönlendirmesi bu şekilde zorlaştırılır).

**Kalan risk:** webhook URL'si doğrulanırken (host allowlist dışında)
gerçek bir SSRF testi/pentest yapılmadı — sadece statik host-suffix
kontrolü var, DNS rebinding gibi daha ileri senaryolar kapsam dışı.

### 10. Ele geçirilmiş admin hesabı

Admin TÜM bulguları görür, kullanıcı/ayar/token yönetebilir — tek ve
değerli bir hedef.

**Kontroller:** Argon2id parola hash, giriş rate-limit + 15 dk kilitleme
(`core/auth.py::MAX_FAILED_LOGIN_ATTEMPTS`), her admin eylemi audit'li,
admin oluşturma/parola sıfırlama panelden de mümkün ama HER ZAMAN audit
log'a yazılıyor (`app/routes_users.py`).

**Kalan risk (artmış, kayıtlı karar):** TOTP kaldırıldığı için (ASSUMPTIONS.md
#14) tek faktör = parola. Rate-limit + kilitleme brute-force'u yavaşlatır
ama engellemez. Parola politikası (min 12 karakter, 3 sınıf) tek savunma
katmanıdır. **Admin sayısını az tutmak ve güçlü/benzersiz parolalar
kullanmak artık daha kritik.**

### 11. Panelden PAT ile repo ekleme (hibrit model, 2026-11-10 kullanici karari)

GitHub App org-wide kurulumuna ek olarak admin panelden tek bir repo icin
fine-grained bir Personal Access Token (PAT) girip ekleyebilir
(`app/routes_repos.py` "+ Proje Ekle", `core.models.RepoOnboardingRequest`/
`RepoCredential`). Bu, App'in GORMEDIGI bir repoya erisim icin yeni bir
secret sinifi ekler -- her biri App private key'inden daha DUSUK yetkili
(tek repo, admin'in GitHub'da sectigi izinler) ama panelden girildigi icin
ayri bir tehdit yuzeyi.

**Kontroller:**
- `app` servisi token'i GitHub'a karsi HIC kullanmaz, SADECE Fernet ile
  sifreleyip DB'ye yazar (`core/backup_crypto.py`, Teams webhook ile AYNI
  mekanizma, AYRI bir anahtar: `REPO_TOKEN_ENCRYPTION_KEY_PATH`) -- token'i
  gercekten kullanan taraf HER ZAMAN orchestrator'dir (App private key'iyle
  AYNI ayrim ilkesi: GitHub'a cikan tek servis orchestrator).
- Token DEGERI hicbir zaman log'a/audit_log'a yazilmaz -- SADECE hangi
  owner/repo icin istek yapildigi audit'lenir (`repo_onboarding_requested`).
- SADECE admin bu formu gorebilir/kullanabilir (`require_admin`).
- Token'in GitHub'a karsi gecerliligi/izni SADECE orchestrator'in
  `GET /repos/{owner}/{repo}` cagrisiyla dogrulanir -- gecersiz/yetkisiz bir
  token hic bir `repositories` satiri OLUSTURMAZ, sadece anlasilir bir hata
  mesaji (`repo_onboarding_requests.error_message`) yazar.
- Token kaldirildiginda (`POST /repositories/{id}/remove-credential`) repo
  otomatik tarama disi (`scan_excluded`) birakilir -- yetkisiz bir token
  sessizce eski (potansiyel olarak yanlis) sonuclar URETMEZ.

**Kalan risk:** Admin'in girdigi PAT'in GERCEKTEN minimum izinli (sadece
Contents/Metadata Read-only) olup olmadigi sunucu tarafinda DOGRULANMAZ --
sadece UI'da bir oneri/hint var (kural: "admin zaten guvenilir bir rol",
Teams webhook SSRF kontrolundeki host-allowlist gibi ek bir teknik kisit
BURADA YOK, cunku hedef sabit `api.github.com`/GHES, admin'in sectigi
degiskenlik GitHub'in kendi yetkilendirme ekraninda kalir). Ayrica TUM
manuel PAT'ler AYNI `REPO_TOKEN_ENCRYPTION_KEY_PATH` anahtariyla sifrelenir
-- bu anahtar sizarsa (Docker secret dosyasina erisim) TUM manuel repo
token'lari tek seferde cozulebilir hale gelir (App private key'inin
tekilligiyle AYNI risk sinifi, bkz. madde 3).

## Özet tablo

| Tehdit | Risk seviyesi (kontrollerden sonra) |
|---|---|
| Kötü niyetli repo içeriği | Düşük (statik parse, escape, validasyon) |
| Symlink/zip-bomb | Düşük (izolasyon katmanları), ampirik test eksik |
| Çalınmış GitHub App key | Düşük (sadece orchestrator, Docker secret) |
| Çalınmış kullanıcı parolası | **Orta-Yüksek** (TOTP yok, tek faktör) |
| Ele geçirilmiş worker | Düşük (ağsız, sanity-gate) |
| İçeriden kullanıcı (viewer) | Düşük (RBAC sunucu tarafı, audit) |
| İçeriden kullanıcı (admin) | Orta (tek faktör, ama audit'li + rate-limit) |
| Zehirlenmiş mirror | Düşük (checksum + tazelik kontrolü) |
| Egress/veri sızdırma | Düşük (bkz. EGRESS_REPORT.md) |
| Panelden PAT ile repo ekleme | Düşük-Orta (şifreli, tek kullanım alanı orchestrator, ama izin kapsamı sunucu tarafında doğrulanmaz) |
