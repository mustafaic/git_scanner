# VERIFIED_FACTS.md

Bu belge master_prompt.md kural 2'nin gereğidir: belgedeki araç bayrakları,
API uç noktaları ve şemalar hafızadan yazılmış ve doğrulanmamıştı. Aşağıdaki
her madde **resmi kaynaktan** (WebSearch/WebFetch ile) doğrulanmıştır;
doğrulanamayan veya kısmi doğrulanan noktalar `docs/ASSUMPTIONS.md`'dedir.

Doğrulama tarihi (hepsi için): **2026-11-08**.

---

## OSV-Scanner

| # | İddia | Durum | Kaynak |
|---|---|---|---|
| 1 | `--offline` flag'i önceden indirilmiş yerel DB'ye karşı tarar; proje/bağımlılık bilgisini hiçbir yere göndermez. | **VERIFIED** | https://google.github.io/osv-scanner/usage/offline-mode/ |
| 2 | Offline DB konumu `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` ortam değişkeniyle belirlenir; DB'yi indirmek/güncellemek için **ayrı** `--download-offline-databases` flag'i gerekir (bu adımda ağ çağrısı olur, ayrı tutulmalı). | **VERIFIED** | aynı kaynak |
| 3 | Manuel DB indirme kaynağı: `gs://osv-vulnerabilities` GCS bucket, `https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip`. | **VERIFIED** | aynı kaynak |
| 4 | SPDX ve CycloneDX SBOM girdisi PURL üzerinden destekleniyor, format dosya adı/içerikten otomatik algılanıyor. | **VERIFIED** | https://google.github.io/osv-scanner/usage/scan-source |
| 5 | `--format json` ile sonuçlar stdout'a JSON yazılır (diğer çıktı stderr'e gider); `sarif`, `spdx-2-3`, `cyclonedx-1-5` formatları da var. | **VERIFIED (üst seviye şema)** | https://google.github.io/osv-scanner/output/ |
| 6 | **KRİTİK — master_prompt.md'nin varsayımını doğruluyor:** OSV-Scanner **varsayılan modda ÇEVRİMİÇİDİR**. Paket adı, sürüm, ekosistem ve dosya hash'lerini osv.dev API'sine ve (bağımlılık çözümleme/lisans/container tarama için) deps.dev API'sine gönderir. "Zero telemetry" iddiası (analitik toplanmıyor) bu API sorgularından **ayrı** bir şeydir — paket/sürüm verisi yine de dışarı çıkar. | **VERIFIED, KRİTİK** | https://github.com/google/osv-scanner/discussions/887 ; https://google.github.io/osv-scanner/usage/offline-mode/ |
| 7 | **Sonuç:** Ürünümüzde OSV-Scanner **her çalıştırmada `--offline` + önceden indirilmiş DB** ile çalıştırılmalı; `--download-offline-databases` çalıştırma anında DEĞİL, orchestrator'ın ayrı mirror-sync adımında (egress-proxy üzerinden, bölüm 3.3) kullanılmalı. | **KARAR (tasarım sonucu, doğrulanmış girdilere dayanır)** | — |
| 8 | **DÜZELTME:** OSV-Scanner'ın resmi desteklenen lockfile tablosunda Go ekosistemi için **`go.mod`** kullanılır, **`go.sum` değil** (Go modüllerinde go.mod zaten tam/pinli sürüm içerir; go.sum salt checksum dosyasıdır). Diğer tam liste: Rust→Cargo.lock, Ruby→Gemfile.lock+gems.locked, PHP→composer.lock, .NET→packages.lock.json/packages.config/deps.json, Java→gradle.lockfile/buildscript-gradle.lockfile/pom.xml/verification-metadata.xml, Python→Pipfile.lock/poetry.lock/requirements.txt/pdm.lock/pylock.toml/uv.lock, JS→package-lock.json/yarn.lock/pnpm-lock.yaml/bun.lock. | **VERIFIED, DÜZELTME UYGULANDI** (`tools/inventory.py` güncellendi) | https://google.github.io/osv-scanner/supported-languages-and-lockfiles/ |
| 9 | SBOM girdisi ile `--offline` modunun birlikte kullanılabildiğine dair resmi dokümanda açık bir doğrulama **bulunamadı** (offline-mode sayfası SBOM'dan bahsetmiyor). | **COULD_NOT_VERIFY** → bkz. ASSUMPTIONS.md | https://google.github.io/osv-scanner/usage/offline-mode/ |

## Gitleaks

| # | İddia | Durum | Kaynak |
|---|---|---|---|
| 1 | `--redact[=percent]`: değersiz verilirse **%100** (tam maskeleme); `--redact=20` gibi kısmi oran da mümkün. | **VERIFIED** | https://github.com/gitleaks/gitleaks |
| 2 | Rapor formatları: `json, csv, junit, sarif` (+ `--report-template`). JSON alanları: `Fingerprint, Secret, File, Line, RuleID, Commit, Author, Email, Date, Message, Entropy, Tags, Match`. Redaction kapalıyken ham secret **`Secret`** alanında düz metin durur. | **VERIFIED** | aynı kaynak |
| 3 | Commit aralığı taraması: `--log-opts` ile `git log -p` sözdizimi (örn. `gitleaks git -v --log-opts="--all commitA..commitB" <repo>`). | **VERIFIED** | aynı kaynak |
| 4 | Varsayılan kural seti binary'ye **gömülü**; öncelik sırası: `--config` > `GITLEAKS_CONFIG` env > `GITLEAKS_CONFIG_TOML` > hedef yolda `.gitleaks.toml` > gömülü varsayılan. Hiçbir online fetch yok. | **VERIFIED** | aynı kaynak |
| 5 | **KRİTİK — master_prompt.md 4.4 ile ÇELİŞİYOR:** Fingerprint = `commitSHA:dosyaYolu:ruleID:satırNumarası`. **Satır numarası değişirse fingerprint DEĞİŞİR** (master_prompt.md'nin "fingerprint kararlı olmalı, satır kayınca yeni bulgu doğmasın" beklentisiyle uyumsuz). | **VERIFIED, ÇATIŞMA — kullanıcı kararı gerekir** | aynı kaynak |
| 6 | Ek mekanizmalar: `gitleaks:allow` satır-içi yorum ile ignore; `.gitleaksignore` (fingerprint listesiyle, v8.10.0+ deneysel); `--baseline-path` ile önceki rapora göre sadece yeni bulgular. | **VERIFIED** | aynı kaynak |
| 7 | Gitleaks'in varsayılan olarak herhangi bir ağ çağrısı/telemetri yaptığına dair resmi bir ifade **bulunamadı** (README'de konu geçmiyor); mimari olarak yerel `git log` çıktısını parse ediyor, tasarım gereği ağ bağımlılığı yok gibi görünüyor ama vendor'dan açık "telemetri yoktur" beyanı yok. | **COULD_NOT_VERIFY (dolaylı kanıt var)** → bkz. ASSUMPTIONS.md | — |

## GitHub REST / GraphQL API

| # | İddia | Durum | Kaynak |
|---|---|---|---|
| 1 | `GET /repos/{owner}/{repo}/git/trees/{tree_sha}` — `tree_sha` parametresi **doğrudan branch/tag adı kabul eder**; önce commit/tree SHA'sına çözmek gerekmez. | **VERIFIED** | https://docs.github.com/en/rest/git/trees |
| 2 | `recursive=1` sorgusunda `truncated: true`, **100.000 girdi** veya **7 MB** toplam boyut aşıldığında döner. | **VERIFIED** | aynı kaynak |
| 3 | Git Blobs API (`/git/blobs/{file_sha}`) **100 MB**'a kadar blob destekler (encoding `utf-8` veya `base64`). Contents API: dosya ≤1 MB ise tam destek; 1 MB–100 MB arası `Accept: application/vnd.github.raw` header'ı gerekir (limit eskiden 1MB'dı, 2022-05-03'te 100MB'a çıkarıldı). | **VERIFIED** | https://docs.github.com/en/rest/repos/contents ; https://github.blog/changelog/2022-05-03-increased-file-size-limit-when-retrieving-file-contents-via-rest-api/ |
| 3b | **Tasarım sonucu:** `tools/inventory.py` artık Contents API değil, **Blobs API** kullanıyor (tree yanıtındaki `sha` alanı üzerinden) — 1MB/100MB Accept-header ayrımıyla uğraşmadan tek, tutarlı bir yol. Bu, master_prompt.md 3.2.4'teki "Blobs API ile indirilir, tam klon gerekmez" tasarımıyla da uyumlu. | **KARAR** | — |
| 4 | GraphQL rate limit: Kullanıcı/PAT 5.000 point/saat; GitHub App installation (Enterprise Cloud dışı) 5.000 + 20'den fazla repo için repo başına +50 point/saat; Enterprise Cloud org/enterprise altı 10.000 point/saat; üst sınır 12.500 point/saat; ikincil limit dakikada 2.000 point. | **VERIFIED (genel limitler)** | https://docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api |
| 4b | Basit bir `repository(owner,name){defaultBranchRef{target{oid}}}` sorgusunun tam point maliyeti (query alanına göre değişir) resmi tablo olarak **bulunamadı** — gerçek org ile Aşama 1/2'de ölçülmesi gerekiyor. | **COULD_NOT_VERIFY** → bkz. ASSUMPTIONS.md | — |
| 5 | `X-Hub-Signature-256`: webhook secret ile **ham (raw) request body** üzerinden HMAC-SHA256; `sha256=<hex>` formatında. Secret tanımlı değilse header hiç gönderilmez. Sabit-zamanlı karşılaştırma şart; body'nin JSON-parse EDİLMEMİŞ ham hali kullanılmalı. | **VERIFIED** | https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries |
| 6 | `X-GitHub-Delivery`: her delivery için benzersiz kimlik; **yeniden gönderimde (redelivery) orijinal delivery ID korunur** → tekrar/idempotency kontrolü için kullanılabilir (imza doğrulamasının yerine geçmez). | **VERIFIED** | aynı kaynak |
| 7 | `GET https://api.github.com/meta` içindeki `hooks` alanı webhook teslimat IP aralıklarını listeler; bu aralıklar **değişebilir** (2026-10-29'da yeni CIDR'ler eklendi) → statik tek-seferlik firewall allowlist yerine **periyodik yenileme prosedürü** gerekir. | **VERIFIED — RUNBOOK'a eklenmeli** | https://github.blog/changelog/2026-10-29-webhook-ip-ranges-added-to-the-meta-api/ ; https://docs.github.com/en/webhooks/using-webhooks/delivering-webhooks-to-private-systems |
| 8 | GHES: REST taban yolu `https://<HOST>/api/v3`; GraphQL taban yolu `https://<HOST>/api/graphql`. Webhook imza/header mekanizması (X-Hub-Signature-256, X-GitHub-Delivery) GHES'te de **aynı**. | **VERIFIED (REST/GraphQL path)**, webhook mekanizması eşitliği dolaylı kanıtla **VERIFIED** | resmi GraphQL guide: https://docs.github.com/en/graphql/guides/forming-calls-with-graphql |
| 9 | GHES'in kendi `/meta` endpoint'inin IP aralığı davranışının GitHub.com'dan farklı olup olmadığı net değil (genelde ilgisiz, çünkü GHES kurumun kendi ağında). | **COULD_NOT_VERIFY** → bkz. ASSUMPTIONS.md | — |
| 10 | GitHub App minimum izinler: `GET /orgs/{org}/repos` (private dahil) → **Metadata: Read-only** yeterli (Administration GEREKMEZ). `git/trees` + `git/blobs` → **Contents: Read-only**. Dependabot alert okuma → ayrı, özel **"Dependabot alerts: Read-only"** izni. | **VERIFIED** | https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps |

---

## GitHub App auth / discovery (Aşama 1 için doğrulandı, 2026-11-08)

| # | İddia | Durum | Kaynak |
|---|---|---|---|
| 1 | JWT zorunlu alanlar: `iss` (App ID veya Client ID), `iat`, `exp`, header `alg: RS256`. Maksimum `exp` penceresi **şu andan 10 dakika** ileri. Saat kayması için önerilen: `iat`'ı **60 saniye geçmişe** ayarla. | **VERIFIED** | https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app |
| 2 | JWT ile çağrıda `Authorization: Bearer <jwt>` kullanılır. | **VERIFIED** | aynı kaynak |
| 3 | `POST /app/installations/{installation_id}/access_tokens` — JWT ile çağrılır, installation access token döner; token **1 saat sonra expire olur**; `permissions` belirtilmezse App'e tanınan tüm izinler token'a geçer (App'in izin kümesini aşamaz). | **VERIFIED** | https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/ |
| 4 | `GET /installation/repositories` — **installation access token** ile (JWT ile DEĞİL) çağrılır; yanıt `{total_count, repositories[], repository_selection}`; `per_page` (max 100, varsayılan 30), `page` ile sayfalanır. | **VERIFIED** | https://docs.github.com/en/rest/apps/installations |
| 5 | `X-GitHub-Api-Version` header değeri: kararlı/sabit sürüm string'i `2022-11-28` (GitHub REST API versiyonlama şeması nadiren değişir; bir dokümantasyon sayfasında dinamik/o-günkü tarih gösterimi görüldü ama bu muhtemelen sayfanın örnek-render kusuru, resmi versiyonlama dokümanında `2022-11-28` güncel sürüm olarak teyit edilmişti — bkz. yukarıdaki GitHub API tablosu madde 8). | **VERIFIED (ana tabloyla çapraz kontrol)** | https://docs.github.com/en/rest/about-the-rest-api/api-versions |

## Özet — tasarım üzerindeki etkiler

1. **OSV-Scanner her zaman `--offline` + önceden indirilmiş DB ile çalıştırılmalı.** Varsayılan davranışa güvenilemez; worker'ın `network_mode: none` olması ikinci güvence katmanı olarak zaten planlanmıştı, bu bulgu onu daha da kritik hale getiriyor.
2. **Go ekosistemi için lockfile sinyali `go.mod`'dur, `go.sum` değil.** `tools/inventory.py` buna göre düzeltildi.
3. **Gitleaks fingerprint'i satır numarasına bağlı ve kararsız.** master_prompt.md 4.4'teki "kararlı fingerprint" beklentisiyle çelişiyor — Aşama 3 tasarımında kullanıcı kararı gerekiyor (bkz. Aşama 0 raporu).
4. **`tools/inventory.py` Contents API yerine Blobs API kullanacak şekilde güncellendi** — boyut limiti ayrımıyla uğraşmadan tutarlı çalışır.
5. **Webhook IP allowlist'i statik değil, periyodik yenileme gerektirir** (Aşama 2b, koşullu modül — henüz onaylanmadı).
6. **KULLANICI KARARLARI (Aşama 0 DUR noktası, 2026-11-08):** (a) Build (DefectDojo değerlendirmesi şimdilik atlandı, sıfırdan inşa edilecek); (b) eşleştirme stratejisi S2 (lockfile tabanlı) onaylandı, bkz. MATCHING_SPIKE.md §6; (c) Gitleaks fingerprint için kendi ikincil fingerprint'imiz (rule ID + dosya yolu + secret-content hash) hesaplanacak, bkz. ASSUMPTIONS.md §3; (d) **webhook modülü (Aşama 2b) KAPALI** — MVP hızlı yoklama + elle tetikleme + günlük uzlaştırma ile ilerleyecek, webhook sonraya bırakıldı.
