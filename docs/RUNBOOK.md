# RUNBOOK.md

İşletim rehberi (master_prompt.md 7 — Aşama 5 deliverable). Tüm komutlar
`deploy/` dizininden çalıştırılır (`cd deploy`).

## 1. Kurulum (ilk kez)

1. `.env` dosyasını oluşturun (`deploy/.env`, git'e girmez):
   ```
   POSTGRES_USER=scanner
   POSTGRES_PASSWORD=<güçlü-bir-parola>
   POSTGRES_DB=scanner
   GITHUB_API_BASE_URL=https://api.github.com
   GITHUB_APP_ID=<app-id>
   GITHUB_APP_INSTALLATION_ID=<installation-id>
   GITHUB_APP_PRIVATE_KEY_PATH=/run/secrets/<key-dosya-adı>.pem
   SESSION_COOKIE_SECURE=false   # SADECE yerel/HTTP dev ortamı; TLS'in ardındaysa true
   BACKUP_ENCRYPTION_KEY_PATH=/run/secrets/backup_encryption_key
   ```
2. `docker compose build` (tüm servisler).
3. `docker compose up -d postgres` → sağlıklı olmasını bekleyin.
4. `docker compose run --rm migrate` (şema oluşturulur, `alembic upgrade head`).
5. `docker compose up -d app orchestrator watchdog worker`.
6. `curl http://localhost:8081/healthz` ve `curl http://localhost:8080/healthz` → `{"status":"ok"}`.

## 2. GitHub App kurulumu

1. GitHub'da bir App oluşturun (Settings → Developer settings → GitHub Apps).
2. İzinler: **Contents: Read-only**, **Metadata: Read-only** (Dependabot
   alert okumak istiyorsanız ayrıca **Dependabot alerts: Read-only**).
   Administration GEREKMEZ (VERIFIED_FACTS.md madde 10).
3. Private key'i indirin (`.pem`), `deploy/secrets/<dosya-adı>.pem` olarak
   koyun (bkz. `deploy/secrets/README.md`).
4. App'i organizasyona/hesaba kurun (Install App), Installation ID'yi not
   edin (URL'de görünür: `.../installations/<ID>`).
5. `.env`'de `GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID`,
   `GITHUB_APP_PRIVATE_KEY_PATH` değerlerini girin, `docker compose up -d
   orchestrator` ile yeniden başlatın.
6. Loglarda `"GitHub App kimligi yuklendi"` mesajını doğrulayın:
   `docker compose logs orchestrator --tail 20`.

**Bilinmeyen nokta (ASSUMPTIONS.md #8):** GHES kullanıyorsanız kurulum
onay akışı farklı olabilir — bu depoda doğrulanmadı.

## 3. İlk admin oluşturma

TOTP kaldırıldığı için (ASSUMPTIONS.md #14) bu artık tek adım:

```
docker compose exec app python tools/create_admin.py --username <kullanıcı-adı> --role admin
```

Parola terminalde `getpass` ile (gizli) istenir. **İlk admin dışındaki**
tüm kullanıcılar (admin veya viewer) panelden (`/users`, admin girişi
gerekir) oluşturulabilir.

## 4. Parola sıfırlama

- **Panelden** (admin başka bir kullanıcının parolasını unuttuğunda):
  `/users` sayfasında ilgili satırda "Parola sıfırla".
- **CLI'dan** (hiçbir admin hesabına giriş yapılamıyorsa — tüm adminler
  kilitli/parolası unutulmuşsa):
  ```
  docker compose exec app python tools/create_admin.py --username <kullanıcı-adı> --reset-password
  ```

## 5. Egress allowlist yönetimi

Allowlist **sunucu/ağ seviyesinde** tutulur (uygulama arayüzünden
değiştirilemez — kasıtlı, master_prompt.md 5). Varsayılan izin verilenler:
- GitHub API (`api.github.com` veya GHES host'u)
- `osv-vulnerabilities.storage.googleapis.com` (OSV-Scanner offline DB)
- `raw.githubusercontent.com` (cisagov/kev-data mirror için — `docs/EGRESS_REPORT.md`'de doğrulanan gerçek host, `cisa.gov` 403 döndürüyor)
- `epss.empiricalsecurity.com` (EPSS)

**Periyodik yenileme gerekli:** `GET https://api.github.com/meta`
içindeki `hooks` alanı GitHub'ın webhook/API IP aralıklarını listeler ve
**değişebilir** (VERIFIED_FACTS.md madde 7: 2026-10-29'da yeni CIDR'ler
eklendi). Statik tek-seferlik bir kural YETERSİZ — bu listeyi periyodik
(ör. aylık) kontrol edip güvenlik duvarı kurallarını güncelleyin.

## 6. Yedekleme ve geri yükleme

**Yedek alma** (manuel veya host cron ile zamanlanmış):
```
docker compose run --rm backup
```
Çıktı: `deploy_backups` Docker volume'üne şifreli bir dosya
(`scanner_backup_<UTC-zaman-damgası>.sql.enc`). Retention varsayılan 14
gün (`BACKUP_RETENTION_DAYS`).

**Host cron örneği** (Linux, günde bir kez 03:00):
```
0 3 * * * cd /path/to/deploy && docker compose run --rm backup >> /var/log/scanner-backup.log 2>&1
```

**Restore testi** (SADECE izole bir hedefe — `postgres-test` veya ayrı bir
konteyner, CANLI DB'ye ASLA):
```
docker compose run --rm restore --backup /backups/<dosya-adı>.sql.enc \
  --target-database-url "postgresql+psycopg://scanner:<parola>@postgres-test:5432/scanner_test"
```
`restore.py` hedef URL, çalışma ortamının CANLI `DATABASE_URL`'iyle
AYNIYSA komutu reddeder (atlanamaz güvenlik kontrolü).

**Anahtar yönetimi:** `deploy/secrets/backup_encryption_key` kaybolursa
hiçbir eski yedek çözülemez. Bu dosyayı AYRICA (ör. bir parola
yöneticisinde) yedekleyin.

## 7. Scanner/DB güncelleme prosedürü

1. OSV-Scanner/Gitleaks yeni sürümü resmi checksum ile doğrulayın
   (VERIFIED_FACTS.md'deki pinleme deseniyle aynı).
2. `deploy/Dockerfile.worker`'da sürüm/digest'i güncelleyin.
3. **Golden-file testlerini** çalıştırın (`tests/unit/test_osv_scanner_adapter.py`,
   `tests/unit/test_gitleaks_adapter.py`) — yeni sürümün çıktı şeması
   değişmediğini doğrular.
4. Gitleaks kural seti güncellenirse (Gitleaks'in gömülü varsayılan kural
   seti) **tam yeniden tarama** tetiklenmeli (master_prompt.md 4.4) —
   `repositories.last_scanned_sha` sütununu ilgili repolar için `NULL`'a
   çekmek bunu zorlar (`orchestrator/secret_scan.py::full_rescan` mantığı).
5. `docker compose build --no-cache worker` + yeniden deploy.

## 8. Sorun giderme

| Belirti | Olası neden | Kontrol |
|---|---|---|
| Orchestrator "skeleton modda" | GitHub App kimliği eksik/okunamıyor | `docker compose logs orchestrator \| grep "GitHub App"` |
| `/healthz` 503 | DB erişilemiyor | `docker compose logs postgres`, `docker compose ps` |
| Bulgular hiç kapanmıyor | Advisory DB bayat | Dashboard'daki "Advisory DB tazeliği" kartına bakın |
| pg_dump/pg_restore sürüm hatası | Client/server sürüm uyuşmazlığı | `deploy/Dockerfile.orchestrator`'da `postgresql-client-16` pinlemesi var mı kontrol edin |
| Panelde giriş döngüsü (sürekli /login) | CSRF cookie engellendi (tarayıcı ayarı) veya `SESSION_COOKIE_SECURE=true` + düz HTTP | `.env`'de `SESSION_COOKIE_SECURE` değerini ortamla eşleştirin |
| Worker işleri hiç tamamlanmıyor | Worker container çökmüş/yeniden başlıyor | `docker compose logs worker`, `docker compose ps worker` |

## 9. Dependabot recall karşılaştırması (bağımsız doğrulama)

Kendi read-only PAT'ınızla (ilgili repolarda `security_events` kapsamı,
GitHub App izinlerine HİÇBİR ŞEY eklenmez) çalıştırın:
```
docker compose run --rm --entrypoint python orchestrator \
  tools/dependabot_compare.py
```
(`DEPENDABOT_COMPARE_TOKEN` ortam değişkeni ile token verin.) Çıktı:
hangi Dependabot alert'lerinin bizim `findings` tablomuzda karşılığı
olmadığını ("KAÇIRILAN", recall gap) ve genel recall yüzdesini raporlar.
Dependabot burada SADECE bağımsız bir doğrulama kaynağıdır, ürün akışına
girmez.

## 10. Heartbeat kurulumu (dead man's switch)

`watchdog` servisi her döngüde son başarılı Hat A/Hat B zamanını kontrol
eder. **Şirket içinde, bu sistemden AYRI bir makinede** çalışan bir
izleyiciye (ör. kendi barındırılan Healthchecks.io/Uptime Kuma) ping
atması için `.env`'de `HEARTBEAT_URL` ayarlayın:
```
HEARTBEAT_URL=https://heartbeat.internal.example/ping/<token>
HEARTBEAT_STALE_THRESHOLD_SECONDS=1800
```
Ping içerik TAŞIMAZ (sadece "yaşıyorum" sinyali). Günlük özetin
GELMEMESİ de bir sinyaldir (madde 6 "Dead man's switch") — ayrıca izleyin.
