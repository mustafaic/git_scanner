# GÖREV: GitHub Repository Security Platform'u baştan sona geliştir (v2)

Sen kıdemli bir yazılım ve uygulama güvenliği mühendisisin. Aşağıdaki ürünü, aşamalı, test edilmiş ve çalıştırılabilir parçalar halinde sıfırdan inşa edeceksin. Kullanıcı Türkçe konuşuyor: açıklamaları Türkçe yaz, teknik terimleri gerektiğinde İngilizce bırak, her önemli kararı nedeniyle kısaca açıkla. Kod, değişken adları, commit mesajları ve doküman başlıkları İngilizce olabilir.

## 0. Çalışma kuralları (pazarlıksız)

1. **Aşama aşama ilerle.** Her aşamanın sonunda: testleri çalıştır, kısa özet ver (ne yapıldı, ne test edildi, neyi doğrulayamadın), `git commit` at ve **kullanıcının onayını bekle**. Onay almadan sonraki aşamaya geçme.
2. **Bu belgedeki araç bayrakları, çıktı şemaları, API uç noktaları ve izin adları hafızadan yazılmıştır ve doğrulanmamıştır.** Kullanmadan önce resmi dokümandan doğrula (web araması varsa kullan). Doğruladıklarını kaynak URL ve tarihle `docs/VERIFIED_FACTS.md`'ye, doğrulayamadıklarını `docs/ASSUMPTIONS.md`'ye yaz. Hafızandan bayrak/şema uydurma.
3. **Sıfırdan scanner, CVE veritabanı, sürüm karşılaştırma motoru veya SAST motoru yazma.** Hazır araçları çalıştır, çıktısını normalize et. Sürüm aralığı eşleştirmesi (semver, PEP 440, Maven vb.) yanlış yazılırsa doğrudan false positive/negative üretir; bunu kendin yazmaya yalnızca Aşama 0b spike'ı başka yol bırakmazsa, olgun bir kütüphaneyle ve kullanıcı onayıyla başla.
4. **Kapsam dışına çıkma.** "MVP dışı" ve "yapma" listelerindeki hiçbir şeyi ben istemeden ekleme.
5. **"Sıfır false positive" garantisi verme ve öyle iddia etme.** Hedef: kanıtlanmış bulgu "Verified", belirsiz olan "Needs Review". Kalite precision/recall ile ölçülür.
6. **Bilinmeyenleri varsayma, konfigürasyona çevir.** Şirketin GitHub tipi (Cloud / Enterprise Server), dilleri, lockfile durumu bilinmiyor. Bunlar config'den gelsin.
7. **Güvenlik bu ürünün ana gereksinimidir** (bölüm 5). Bu sistem şirketin tüm private kodunu okuyacak; kendisi yüksek değerli bir hedeftir.
8. **Gerçek token/secret'ı asla sohbete yazdırma, koda gömme, loglama.** Her zaman ortam değişkeni veya Docker secret/dosya.
9. Küçük, test edilebilir parçalar üret. Çalıştırmadığın kodu "çalışıyor" diye raporlama.
10. Görev listesi (TaskCreate/TaskUpdate) kullan; her aşamanın son maddesi "çalıştırıp doğrula" olsun.
11. **Basit olanı seç, ölç, sonra optimize et.** Her mimari karmaşıklık için yazılı gerekçe gerekir. Ölçmediğin performans sorununu çözmek için karmaşıklık ekleme.
12. **Şirkete ait hiçbir hassas veri dış internete çıkmaz (en üst öncelikli ilke).** Repo içeriği, repo/dosya/paket adları, bağımlılık listesi, bulgular, secret'lar ve kullanıcı bilgileri dahil. Bu ilke her bileşen, araç ve özellik için geçerlidir ve bölüm 5'teki egress politikasında somutlaştırılmıştır. Bir araç veya özellik veri gönderiyorsa (çevrimiçi sorgu, telemetri, hata raporlama, güncelleme kontrolü) varsayılan olarak kapat ve kapandığını doğrula; kapatamıyorsan kullanma ve bana bildir.

## 1. Ürün tanımı ve tasarım ilkeleri

Şirket network'ünde bir sunucuda Docker Compose ile **sürekli ve otomatik** çalışan, şirketin GitHub repolarındaki bağımlılık zafiyetlerini ve sızmış secret'ları izleyen, bulguları **tek ortak modelde** birleştiren, doğrulayan, tekilleştiren, önceliklendiren ve **sahibine aksiyon olarak ulaştıran** bir güvenlik platformu. Gerçek bir ürün: demo değil. Hem GitHub.com hem GitHub Enterprise Server'da çalışabilmeli (API base URL ve auth konfigüre edilebilir).

Tasarım ilkeleri (her karar bunlara göre tartılır):
- **Bulgu bulmak değil, bulguları kapatmak.** Ham liste değil, aksiyon: "şu paketi şu sürüme yükselt, şu 7 bulgu kapanır, sahibi şu takım."
- **Şirket verisi dışarı çıkmaz.** Zafiyet veritabanları gibi herkese açık verilerin indirilmesi serbesttir; ama şirkete ait hiçbir bilgi (paket adı dahil) dışarıya sorulmaz, gönderilmez veya dış servislere loglanmaz. Ürün hiçbir noktada AI/LLM veya benzeri harici analiz servisi kullanmaz.
- **Gürültü bütçesi.** Geliştirici ekranı kısa olmalı. İlk taramadaki devasa backlog yeni bulguları boğmamalı (baseline modu, bölüm 6/A6).
- **Kesinlik şeffaf olmalı.** Her bulgu "neden Verified / neden Needs Review" kanıtını gösterir.
- **Sessiz bozulma en büyük düşman.** Tarama durursa, veri bayatlarsa, parser sessizce bir şeyi kaçırırsa sistem bunu **yüksek sesle** söylemeli. "Taranmayan = temiz" yanılgısı engellenir.
- **Zaman kazandır:** tek tıkla blast radius, grup halinde aksiyon, toplu gerekçeli suppression, sahibine yönlendirme, günlük tek özet.

### Çekirdek gereksinimler

- Sürekli izleme: repo değişiklikleri sabit bir periyoda takılmadan, dakikalar içinde yakalanır (hızlı yoklama, elle tetikleme ve isteğe bağlı webhook; bölüm 3.5), yeni yayınlanan advisory'ler günlük; GitHub org repo discovery (private repolar dahil).
- Varsayılan görünüm politikası: **CVSS ≥ 7.0 VEYA CISA KEV'de olan** SCA bulguları. (Orijinal istek "CVSS ≥ 7"ydi; KEV'de olup CVSS'i düşük/yok bir zafiyetin gizlenmesi güvenlik açısından yanlış olduğu için politika bu şekilde genişletildi. Politika config'den değiştirilebilir ve ekranda hangi kuralın uygulandığı yazar.) Düşük skorlular **silinmez**, DB'de tutulur, filtreyle erişilir.
- Skoru olmayan / henüz skorlanmamış advisory = gizli değil, **Needs Review**.
- Skor kaynağı çelişkisinde (GHSA / NVD / vendor, v3.1 / v4.0) hangi kaynağın esas alındığı kayıtlı ve konfigüre edilebilir olsun; çelişki gösterilsin.
- Her bulguda **patchability** (bölüm 4.1).
- Bulgu geçmişi: kapananlar silinmez, arayüzde üzeri çizili/soluk, yanında kapanma tarihi ve kapatan sürüm.
- Tarama/eşleştirme başarısızsa **hiçbir bulgu RESOLVED olmaz** (bölüm 4.3).

## 2. Kapsam

**MVP içi:**
- OSV-Scanner motoru ile SCA (lockfile'lı repolar), Gitleaks ile secret taraması. Her ikisi adaptör arayüzü arkasında.
- **İki ayrı hat:** envanter çıkarma (repo değişince) ve eşleştirme (her gün, repoya dokunmadan). Bölüm 3.
- CISA KEV + EPSS zenginleştirmesi (günlük, offline mirror).
- Ortak Finding modeli, dedup, alias eşleştirme, patchability, lifecycle, audit log.
- Auth: yerel hesaplar, **iki rol**: `admin` (tam yetki, kullanıcı yönetimi dahil) ve `viewer` (salt okunur). Admin için zorunlu TOTP. Harici kimlik sağlayıcı yok.
- **Değişiklik algılama ve tetikleme (bölüm 3.5):** hızlı yoklama (varsayılan), elle tetikleme, koşullu opsiyonel webhook modülü, debounce ve öncelikli kuyruk.
- Özellikler A1–A10 ve iletişim modeli (bölüm 6).
- Ayarlar sayfası ve bildirimler: iç SMTP ve opsiyonel Teams webhook; ikisi de admin tarafından uygulama içinden açılıp kapatılır (varsayılan kapalı). Şirket içi heartbeat + watchdog; egress-proxy.
- Docker Compose dağıtımı, şifreli yedek, test fixture'ları, precision/recall raporu.

**v1.1 (şemada ve arayüzde yer ayır, MVP'de yapma):** GitHub Issues / Azure DevOps'ta konsolide ticket açma (ayrı, yazma izinli App gerektirir; MVP read-only kalır), Trivy (Dockerfile/IaC/image), `developer` rolü (yorum ve suppression talebi; MVP'de yalnızca admin/viewer vardır), CycloneDX/VEX export, PR security gate (yalnızca PR'ın eklediği yeni zafiyet için), otomatik fix PR + doğrulama, default dışı branch'ler/tag'ler.

**Yapma / kapsam dışı:** kendi SAST motoru, AI/LLM tabanlı her türlü analiz, **çevrimiçi eşleştirme servisleri (OSV API dahil: paket adı/sürüm sorgusu şirketin bağımlılık listesini ve şirket-içi paket adlarını dışarı verir)**, secret'ın canlı olup olmadığını sağlayıcıya göndererek doğrulama (secret'ı üçüncü tarafa yollamak demektir), harici telemetri/hata raporlama/log/izleme servisleri, repoda `install`/build/script çalıştırma, reachability analizi, commit yazarlarına göre otomatik sahiplik atama (gürültülü, ayrılmış çalışanlara gider, kişisel veri üretir), React SPA, Celery/Redis, harici kimlik sağlayıcı (OIDC/SSO).

## 3. Mimari

### 3.1 Temel fikir: envanter çıkarma ile eşleştirmeyi ayır

Her gün her repoyu baştan taramak hem yavaş hem gereksizdir; yalnızca "yeni commit'leri taramak" ise envanterdeki mevcut bir bileşen için **sonradan yayınlanan yeni CVE'yi** kaçırır. İkisi ayrı işlerdir:

```
HAT A: ENVANTER ÇIKARMA (yalnızca repo değişince)        HAT B: EŞLEŞTİRME (her gün, repoya dokunmaz)
 GitHub default branch HEAD SHA değişti mi?               Advisory mirror + KEV + EPSS senkronu
   hayır -> atla (günlerin çoğu)                          Güncel snapshot'lardaki BENZERSİZ
   evet  -> lockfile yollarını bul, blob SHA'ları           (ekosistem, paket, sürüm) kümesini çıkar
            karşılaştır; değişenleri çıkar                 Offline advisory DB'ye karşı eşleştir
 -> component_snapshots'a yaz, eski snapshot ile fark      Mevcut bulgularla kıyasla -> olaylar
```

- **Yeni CVE tespiti:** Kod değişmese bile Hat B her gün envanteri güncel advisory'lere karşı eşleştirir. Repoyu tekrar taramaya gerek yoktur.
- **MVP'de advisory-delta optimizasyonu yapma:** Hat B her gün **tüm benzersiz bileşenleri** baştan eşleştirir. Benzersiz bileşen sayısı repo sayısından çok küçüktür (aynı `lodash@x` yüzlerce repoda tek kayıt) ve bu hem daha basit hem daha doğrudur (delta takip hatası riski yok). Süreyi ölç, `docs/PERF.md`'ye yaz; yalnızca ölçüm sorun gösterirse optimize et.

### 3.2 Hat A ayrıntıları (envanter çıkarma)

1. Bir tetikleyici (bölüm 3.5) geldiğinde orchestrator ilgili repo için default branch HEAD SHA'sını GitHub API'den okur (tetikleyicinin taşıdığı veriye güvenilmez). `last_seen_sha` ile aynıysa iş biter.
2. SHA farklıysa: **Git Trees API (recursive)** ile manifest/lockfile yollarını bul; her dosyanın **blob SHA**'sını son snapshot ile karşılaştır. Hiçbir manifest/lockfile blob'u değişmediyse (çoğu commit böyledir) **yeniden çıkarma yapma**, sadece `last_seen_sha`'yı güncelle.
3. Çıkarma sonucu **içerik-adresli önbellek** olarak tutulur: anahtar `(blob_sha, parser_version)`. Aynı blob başka repoda/commit'te görülürse yeniden parse edilmez.
4. Sadece değişen/yeni manifest+lockfile dosyaları **Git Blobs API ile** indirilir; tam klon gerekmez (SCA için). Tree yanıtı `truncated` gelirse veya dosya sayısı/boyutu limiti aşılırsa güvenli yedek yol: sığ (shallow) klon. API detaylarını, limitleri ve GHES farklarını doğrula.
5. Girdi sertliği: `mode 120000` (symlink) girdileri **asla** takip edilmez/atlanır; dosya boyutu üst limiti; toplam dosya sayısı limiti; yol normalizasyonu (job dizininden taşma yok).
6. Parse (worker, bölüm 3.4) sonucunda bileşen listesi: PURL, ekosistem, ad, çözülmüş sürüm, scope (prod/dev/optional), direct/transitive (bilgi varsa, yoksa `unknown`), lockfile yolu, blob SHA.
7. **Doğrulama kapısı (sanity gate):** Orchestrator hangi dosyaları hangi blob SHA ile hazırladığını bilir. Worker sonucu her dosya için `path + blob_sha + status` döndürmek zorundadır; eksik/uyumsuz/başarısız dosya → o scan `PARTIAL`. Önceki snapshot'a göre bileşen sayısı beklenmedik biçimde çökerse (config'de eşik, örn. %50 ve mutlak limit) sonuç otomatik kabul edilmez, `NEEDS_REVIEW` olarak işaretlenir ve **hiçbir bulgu kapatılmaz**. Gerekçe: ele geçirilmiş/hatalı bir worker "boş sonuç" döndürüp bulguları kapattırabilir.
8. Monorepo: bir repoda birden çok lockfile olur; başarı/başarısızlık **lockfile bazında** izlenir. Biri parse edilemezse yalnızca onun bulguları etkilenmez (kapanmaz), diğerleri normal işlenir.
9. Silinen/arşivlenen/erişilemeyen repo: durum olarak kaydedilir, bulgular **sessizce kapatılmaz** (Coverage panelinde görünür).

### 3.3 Hat B ayrıntıları (eşleştirme)

Günlük sıra: (1) advisory mirror senkronu (zaman damgası, sürüm/checksum kaydı), (2) KEV ve EPSS senkronu (kaynak tarihi kayıtlı), (3) benzersiz bileşen kümesi, (4) offline eşleştirme (worker, network'süz), (5) mevcut bulgularla fark → olaylar, (6) zenginleştirme (KEV/EPSS), SLA tarihleri, (7) metrik snapshot'ı, (8) günlük özet.

- **Eşleştirme stratejisi Aşama 0b spike'ıyla seçilecek** (`docs/MATCHING_SPIKE.md`): OSV-Scanner'ın kendi eşleştirme motorunu yeniden kullanmak tercih edilir (kendi sürüm karşılaştırmanı yazma). Adaylar: (S1) envanterden üretilen SBOM'u OSV-Scanner'a **offline** DB ile vermek, (S2) saklanan lockfile blob'larını OSV-Scanner'a **offline** DB ile vermek. **Çevrimiçi seçenek (OSV API vb.) yoktur**: bileşen sorgusu şirketin bağımlılık listesini ve şirket-içi paket adlarını dışarı verir. OSV-Scanner'ın varsayılan çalışma modunun çevrimiçi olabileceğini varsay; offline modun gerçekten ağ çıkışı üretmediğini ağsız ortamda doğrula. S1 ve S2'nin ikisi de tamamen offline çalışamıyorsa **dur ve bana bildir**; alternatifler (ör. ayrı makinede indirip içeri aktarma, olgun bir kütüphaneyle kendi eşleştirmen) benimle onaylanır. OSV-Scanner'ın offline DB, SBOM girdisi ve JSON şeması desteğini resmi dokümandan **doğrula**. Seçim ölçülebilir kritere dayanır: fixture'larda doğruluk, süre, offline çalışabilme.
- Envanter (bileşenler ve snapshot'lar) eşleştirme stratejisinden bağımsız olarak DB'de sorgulanabilir olmalı (blast radius, coverage için).
- **Bulgu kapatma için ek koşul:** advisory mirror senkronu ve eşleştirme çalıştırması **başarılı** olmalı ve DB taze olmalı (maksimum yaş config'de). Bayat/başarısız Hat B hiçbir bulguyu kapatmaz.
- **Commit sonrası anında eşleştirme:** Hat A yeni bir snapshot ürettiğinde, yalnızca o snapshot'taki **yeni** benzersiz bileşenler için hemen bir eşleştirme job'ı çalışır (mevcut advisory DB'ye karşı). Böylece bir commit'in getirdiği zafiyet günlük döngüyü beklemeden dakikalar içinde görünür. Günlük tam eşleştirme ayrıca devam eder.
- Withdrawn/geri çekilmiş advisory: bulgu sessizce silinmez; gerekçeli ve kaynağıyla `RESOLVED`.

### 3.4 Servisler ve izolasyon

```
[proxy]  Caddy/nginx, TLS, tek dış giriş
[app]    FastAPI + Jinja2 + HTMX paneli, yerel auth (admin/viewer), API. GitHub key'i görmez, dış ağ erişimi yoktur.
[orchestrator]  GitHub'a ve mirror kaynaklarına yalnızca egress-proxy üzerinden erişen servis. App private key'i burada. Zamanlayıcı,
                discovery, SHA/tree kontrolü, blob indirme, advisory/KEV/EPSS mirror,
                job kuyruğu, ingest, bildirim.
[worker]  network_mode: none. Yalnızca "o anki job" dizinini okur, result yazar.
          OSV-Scanner / Gitleaks / parser çalıştırır.
[postgres]  Dışarı açılmaz.
[backup]  Şifreli günlük pg_dump + retention + sunucu dışına kopya.
[watchdog]  Küçük, bağımsız süreç: DB'deki "son başarılı döngü" zamanını ve orchestrator
            sağlığını izler; şirket içi (ayrı bir makinedeki) heartbeat izleyicisine ping atar.
[egress-proxy]  Dışarıya çıkışın TEK noktası: alan adı allowlist'li forward proxy (TLS'i açmaz, içerik görmez).
                orchestrator internete doğrudan değil, yalnızca buradan çıkar (app'in dış erişimi yoktur; bildirimleri orchestrator gönderir).
[webhook-receiver]  OPSİYONEL (compose profile, varsayılan kapalı, bölüm 3.5): GitHub push olaylarını alan minimal servis.
                    DB'ye yalnızca `scan_triggers` tablosuna INSERT yapabilen kısıtlı rolle bağlanır.
```

Kararlar ve nedenleri:
- **Kalıcı iş kuyruğu Postgres'te** (`jobs` tablosu, `SELECT ... FOR UPDATE SKIP LOCKED`, `attempts`, `idempotency_key`, `locked_until`, `priority`; tetikleyiciler `scan_triggers` tablosuna düşer, bkz. 3.5). Celery/Redis yok ama bellek-içi zamanlayıcının aksine çökmeye dayanıklı, yeniden denenebilir, idempotent. Job anahtarı: `(tip, repo, sha/blob_sha, scanner_version)`.
- **Worker ile iletişim dosya tabanlı.** Orchestrator **aynı anda yalnızca bir job'u** worker'ın görebildiği dizine hazırlar (just-in-time staging); worker yalnızca onu görür, bitince sonucu yazar, orchestrator dizini temizler. Böylece ele geçirilmiş bir worker diğer repoların kodunu göremez. Daha fazla paralellik gerekirse her worker kendi slot volume'üne sahip olur.
- **Docker socket hiçbir servise mount edilmez.**
- Secret taraması için orchestrator repo başına kalıcı bir **bare mirror önbelleği** tutar (`git fetch`), job için yalnızca o repoyu hazırlar; commit aralığı `last_scanned_sha..HEAD`. Mirror önbelleği disk üzerinde private kod demektir: disk şifreleme (host seviyesinde), retention ve silinen repo için temizlik zorunlu, `docs/THREAT_MODEL.md`'de yer alır.
- Stack: Python 3.12, FastAPI, SQLAlchemy + Alembic, PostgreSQL 16, Jinja2 + HTMX (static dosyalar self-host, CDN yok), pytest. Gerekçeli sapma önereceksen önce sor.
- **Adaptör arayüzü:** her scanner `run(job_dir) -> ham çıktı` ve `parse(ham çıktı) -> list[Finding]` sözleşmesini uygular. Yeni araç (ör. Trivy) yeni adaptör olmalı, çekirdeği değiştirmemeli. Her adaptör için **kaydedilmiş gerçek araç çıktılarıyla golden-file testi**; araç sürümü yükseltilince bu testler zorunlu.
- Zaman: DB'de UTC, panelde konfigüre edilebilir saat dilimi (varsayılan Europe/Istanbul).
- Gözlemlenebilirlik: yapılandırılmış JSON log (secret maskeleme), Prometheus uyumlu `/metrics` (son başarılı döngü, kuyruk uzunluğu, job süreleri, hata sayıları, commit→bulgu gecikmesi, tetikleme gecikmesi, GitHub rate limit bütçesi).

Repo yapısı (öneri, gerekçeyle değiştirilebilir):
```
/app            FastAPI, şablonlar, auth (yerel, TOTP), admin/viewer RBAC, API, ayarlar
/core           Finding modeli, normalizasyon, dedup, doğrulama, lifecycle, öncelik/SLA
/adapters       osv_scanner.py, gitleaks.py (ortak arayüz)
/orchestrator   discovery, github client, hat A (extract), hat B (match), mirror sync, jobs, ingest, notify
/worker         scanner çalıştırma (sadece job dizini okur/yazar)
/watchdog       bağımsız sağlık izleyici + heartbeat
/migrations     Alembic
/tests          fixtures/, unit, integration, quality, security
/deploy         docker-compose.yml, Dockerfile'lar, backup scripti
/docs           VERIFIED_FACTS.md, ASSUMPTIONS.md, THREAT_MODEL.md, RUNBOOK.md,
                DEFECTDOJO_EVAL.md, MATCHING_SPIKE.md, PERF.md, LIMITATIONS.md, EGRESS_REPORT.md
/tools          inventory.py, dependabot_compare.py
```

### 3.5 Değişiklik algılama ve tetikleme

Hedef: bir commit atıldığında kullanıcının sabit bir periyoda denk gelmesini beklememesi. Üç tetikleyici aynı yere akar: `scan_triggers` tablosu → `jobs` kuyruğu (bölüm 3.4). Tetikleyici yalnızca "bu repoyu şimdi kontrol et" der; **gerçek durum her zaman GitHub API'den kendi token'ımızla okunur**, tetikleyicinin taşıdığı veriye güvenilmez (sahte tetikleyici en kötü ihtimalle zararsız bir fazladan kontrol üretir).

1. **Hızlı yoklama (MVP, varsayılan; gelen bağlantı gerektirmez):** her 60 saniyede (config) GraphQL ile **toplu** HEAD SHA sorgusu (tek sorguda çok repo; sorgu maliyetini ve limitleri resmi dokümandan doğrula). Yalnızca SHA'sı `last_seen_sha`'dan farklı olan repolar için iş üretilir. Rate limit bütçesi yetmezse sıcak/soğuk katmanlama (son N günde commit alan repolar 60 sn, diğerleri birkaç dakikada bir) uygula; bunu yalnızca ölçüm gerektiriyorsa yap (kural 11).
2. **Elle tetikleme:** admin panelinde repo bazlı ve toplu "Şimdi kontrol et" düğmesi ve API. Ayarlardan viewer'lara açılabilir (varsayılan kapalı, hız limitli). Aynı SHA zaten işlenmişse yeni iş üretmez.
3. **Webhook "kapı zili" (koşullu, opsiyonel modül, compose profile ile varsayılan kapalı; Aşama 2b):** GitHub `push` olayı gelince saniyeler içinde tetikler. Ayrı, minimal bir `webhook-receiver` servisi: `X-Hub-Signature-256` HMAC'ini sabit-zamanlı karşılaştırmayla doğrular (secret Docker secret'ta), `X-GitHub-Delivery` ile tekrarı eler, yalnızca `push`/`ping` ve default branch'i kabul eder, gövde boyutu sınırlıdır, payload'dan yalnızca repo kimliğini alıp `scan_triggers`'a bir satır yazar (DB rolü yalnızca o tabloya INSERT yapabilir, başka hiçbir şeye erişemez). **Güvenlik bedeli:** bu modül şirket ağına **gelen** bir bağlantı demektir (egress politikasını bozmaz ama saldırı yüzeyi ekler). Yalnızca GitHub'ın webhook IP aralıklarına açık güvenlik duvarı kuralı + TLS + ayrı alan adı gerekir ve ağ/güvenlik ekibinin onayı şarttır. GHES kullanılıyorsa trafik iç ağda kalır ve risk azalır. Bu modülün açılıp açılmayacağına Aşama 0 raporuna göre ben karar veririm; onay gelmeden uygulama.
4. **Güvence ağı (her zaman açık):** yoklama da webhook da bir olayı kaçırabilir (ağ kesintisi, rate limit, receiver kapalıyken gelen olay). Bu yüzden günlük uzlaştırma (tüm repoların HEAD SHA'sı ile `last_seen_sha` karşılaştırması) ve haftalık tam yeniden çıkarma devam eder.

Tetikleme sonrası kurallar:
- **Debounce ve birleştirme:** aynı repo için kısa pencerede (config, örn. 20 sn) gelen tetikleyiciler tek işe birleşir. İş çalışırken yeni SHA gelirse iş bitince **bir kez daha** çalışır ("son SHA kazanır"); ara commit'ler için ayrı iş açılmaz (secret taraması `last_scanned_sha..HEAD` aralığıyla hepsini zaten kapsar).
- **Öncelik:** `jobs.priority`: tetikleyiciyle gelen taze commit işleri toplu işlerden (tam yeniden eşleştirme, haftalık tam çıkarma, mirror senkronu) önce çalışır; toplu işler taze commit'i bekletmez.
- **İdempotent ve repo başına tekil:** iş anahtarı `(tip, repo, sha)`; aynı SHA iki kez işlenmez; bir repo için aynı anda tek iş çalışır.
- **Rate limit dayanıklılığı:** tetikleyici fırtınasında (toplu push) kuyruk sınırlı hızda boşaltılır, GitHub rate limit kalan bütçesi izlenir, bütçe bitince geri çekilir. Gecikme **sessiz olmaz**: panelde (A3) ve sistem sağlığı bildiriminde görünür.
- **Gecikme ölçümü:** `commit_to_finding_seconds` (commit zamanından bulgunun panelde görünmesine) ve `trigger_detection_seconds` metrikleri `/metrics`'te. Hedef taslağı (taahhüt değil; Aşama 2'de ölç ve `docs/PERF.md`'ye yaz): yoklama modunda birkaç dakika, webhook modunda bir dakikanın altı.

## 4. İş kuralları (doğru yazılması kritik)

### 4.1 Patchability (iki ayrı kavram)
`fix_status`: `PATCH_AVAILABLE`, `NO_FIX_YET`, `FIX_UNKNOWN`; ayrıca `fix_version` (kaynağıyla). "Üretici fix yayınladı" ile "bu projeye uygulanabilir" **aynı şey değildir**: MVP'de yalnızca birincisi hesaplanır, ikincisi `NOT_TESTED` kalır. Diğer statüler (WONT_FIX, CONSTRAINT_BLOCKED, WORKAROUND) şemada yer alır, MVP'de üretilmez.

**Önerilen yükseltme sürümü:** Bir paket@sürüm için birden çok zafiyet varsa önerilen sürüm, **hepsini kapatan en küçük** sürümdür (her zafiyetin düzeltilmiş sürümleri arasından, mevcut sürümden büyük, mümkünse aynı major'da). Major atlama gerekiyorsa açıkça "major yükseltme, kırıcı değişiklik riski" olarak işaretlenir. Bu hesap ekosistemin sürüm kurallarıyla yapılır (string karşılaştırması yok); güvenilir hesaplanamıyorsa öneri üretilmez, `FIX_UNKNOWN` kalır.

### 4.2 Verified vs Needs Review
- **Verified:** paket kimliği (PURL/ekosistem/ad/sürüm) net, **lockfile'dan çözülmüş tam sürüm**, advisory affected aralığı ekosistemin sürüm semantiğiyle eşleşiyor, DB taze.
- **Needs Review:** skor yok, kaynaklar çelişiyor, sürüm belirsiz, advisory eksik, sanity gate uyarısı. Needs Review kuyruğu **neden kategorisine** göre filtrelenebilir.
- **Lockfile'sız manifest** (ör. `requirements.txt`'te `>=` aralığı): çözülmüş sürüm yoktur → asla Verified olamaz; `UNVERIFIED_NO_LOCKFILE` ile işaretlenir ve Coverage'da görünür.
- Doğrulanamayan bulgu sessizce silinmez; kanıt ve "neden doğrulanamadı" saklanır.

### 4.3 Lifecycle
Durumlar: `OPEN`, `IN_PROGRESS`, `RESOLVED`, `REOPENED`, `FALSE_POSITIVE`, `NOT_AFFECTED`, `ACCEPTED_RISK`.
- Değişiklikler `finding_events`'e **append-only** yazılır (kim/ne zaman/neden/kanıt). `findings` güncel durumu tutar.
- **RESOLVED için hepsi gerekir:** (a) ilgili lockfile için çıkarma **başarılı ve tam** (PARTIAL değil, sanity gate geçti), doğru commit SHA/blob SHA üzerinde; (b) bileşen yeni snapshot'ta yok ya da artık etkilenmiyor, ya da advisory withdrawn; (c) Hat B başarılı ve DB taze. Scan/clone/parse hatası, timeout, eksik lockfile, bayat DB, sanity gate uyarısı → **hiçbir bulgu kapatılmaz**.
- Kapanmış bulgu tekrar görünürse `REOPENED`, geçmişi korunur.
- Suppression/FP/NOT_AFFECTED/ACCEPTED_RISK: yalnızca admin, **zorunlu gerekçe** (kategori + metin), opsiyonel bitiş tarihi. Aynı bulgu başka repo/sürümde otomatik suppress edilmez. **Toplu işlem** (bir aksiyon grubundaki N bulgu) desteklenir: işlem öncesi etkilenen tüm bulgular listelenip açık onay alınır, her biri ayrı event/audit olarak kaydedilir.

### 4.4 Secret bulguları (SCA'dan farklı kurallar)
- Secret, koddan silinince **RESOLVED olmaz**; git geçmişinde kalır. Kapanış koşulu: admin'in "**rotate edildi / iptal edildi**" onayı (+ not). Koddan kaldırılmış olması yalnızca ara sinyaldir (`FIX_PENDING` benzeri).
- **Ham secret değeri DB'ye, loglara, API yanıtına, panele, bildirimlere asla yazılmaz.** Gitleaks'in redaction seçeneğini kullan (doğrula); kural ID, dosya, commit, satır, fingerprint sakla.
- Secret'ların CVSS'i yoktur; ayrı severity haritası kullan ve belgele. Secret bulguları default görünümde ayrı sekme/rozetle görünür (kaybolmasın). Secret bulguları için **anlık bildirim seçeneği** (config; yalnızca iç kanallar. Secret değeri içermez; repo/dosya/kural bilgisi yalnızca iç SMTP gibi iç kanallara gider, bulut kanallarına yalnızca "yeni secret bulgusu" + iç panel bağlantısı çıkar) — günlük özeti beklemez.
- İlk çalıştırmada tam geçmiş (uzun sürebilir), sonra yalnızca `last_scanned_sha..HEAD`. **Force-push, geçmiş yeniden yazımı veya kural seti güncellemesinde tam yeniden tarama** zorunlu.
- Fingerprint kararlı olmalı (satır kayınca yeni bulgu doğmasın): kural ID + dosya + commit/içerik hash'i yaklaşımı. Bilinen test/örnek secret'lar için fingerprint bazlı, gerekçeli, süreli allowlist.

### 4.5 Dedup ve kimlik
- SCA finding doğal anahtarı: repo + lockfile yolu + component (PURL+sürüm) + canonical vulnerability ID. CVE/GHSA/OSV alias'ları tek canonical kayda bağlanır.
- Finding birden çok kaynaktan kanıt alabilir (`scan_sources`).
- Her scan/match run: repo, branch, commit SHA, lockfile blob SHA'ları, scanner adı+sürümü, advisory DB zaman damgası/checksum'ı, ham çıktı referansı.
- Eşleştirme benzersiz bileşen üzerinden yapılır, sonuç snapshot→repo ilişkisiyle bulgulara dağıtılır.

### 4.6 Önceliklendirme (açıklanabilir)
Sıralama: **KEV'de olan > EPSS yüksek > CVSS > bulgunun yaşı**; scope (prod/dev) ve direct/transitive **rozet olarak** gösterilir. Dev scope otomatik "zararsız" sayılmaz (CI/CD saldırı yüzeyi). Her satırda "neden bu sırada" bilgisi görünür (kara kutu skor yok). KEV ve EPSS kaynak tarihleriyle saklanır; senkron başarısız olursa eski değer "bayat" etiketiyle gösterilir, bulgu kapatma kararlarını etkilemez.

## 5. Güvenlik gereksinimleri

**Veri çıkışı (egress) politikası — en üst öncelik**
- Prensip: şirkete ait hiçbir bilgi (repo içeriği, repo/dosya/paket adı, bağımlılık listesi, bulgu, secret, kullanıcı bilgisi) dış internete çıkmaz. Dışarıyla trafik yalnızca şunlarla olabilir: (a) GitHub (kodun zaten bulunduğu yer; GHES ise iç ağ), (b) **herkese açık verinin indirilmesi** (advisory/KEV/EPSS), (c) admin tarafından bilinçli açılan opsiyonel kanal: Teams webhook (yalnızca minimal içerik; istek içeriğinde ayrıntılı şirket bilgisi taşınmaz).
- Ağ topolojisi: worker, postgres ve app için dış ağ yok; orchestrator doğrudan internet erişimi olmayan `internal` Docker ağında, dışarı yalnızca `egress-proxy` üzerinden çıkar. Proxy'de alan adı allowlist'i (yalnızca sunucu config'i ile yönetilir; uygulama arayüzünden değiştirilemez, böylece ele geçirilmiş bir admin hesabı egress açamaz. Varsayılan: GitHub/GHES host'u, advisory/KEV/EPSS kaynakları; etkinleştirilirse Teams webhook alan adı). Buna ek olarak host/ağ güvenlik duvarında varsayılan-engelle egress kuralı önerilir (RUNBOOK'ta belgele; sunucuyu yöneten ekiple uygulanır).
- Advisory/KEV/EPSS: yalnızca **toplu dosya indirme** (yön: içeri). Bileşen/paket bazlı çevrimiçi sorgu **yasak** (OSV API dahil).
- Scanner'lar (OSV-Scanner, Gitleaks ve ileride eklenecekler): çevrimiçi eşleştirme, otomatik DB güncelleme, telemetri ve sürüm kontrolü özellikleri **kapalı** olmalı; varsayılanların çevrimiçi olabileceğini varsay, resmi dokümandan doğrula ve `docs/VERIFIED_FACTS.md`'ye yaz. Worker'ın ağsız olması ikinci güvencedir; orchestrator tarafında çalışan her araç için aynı ayarlar geçerlidir.
- Bildirimler: kanallar admin tarafından uygulama içinden açılıp kapatılır, varsayılan kapalı. **İç SMTP** ayrıntılı içerik taşıyabilir. **Teams webhook** (bulut) yalnızca `minimal` içerik taşır: sayılar + iç panel bağlantısı; repo/paket/CVE ayrıntısı ve secret bilgisi Teams'e çıkmaz, Teams için `detailed` seçeneği yoktur. Teams webhook URL'si bir secret'tır: DB'de uygulama seviyesinde şifreli saklanır (anahtar Docker secret'ta), arayüzde kaydedildikten sonra bir daha gösterilmez, loglanmaz; admin "test mesajı" gönderebilir. Webhook alan adı proxy allowlist'inde yoksa arayüz bunu açık bir hata olarak gösterir (allowlist arayüzden değiştirilemez; ops ekler).
- Gelen trafik: panel yalnızca iç ağdan erişilir; internete açık hiçbir uç nokta yoktur. Tek istisna, onayımla açılabilecek opsiyonel webhook alıcısıdır (bölüm 3.5): yalnızca GitHub IP aralıklarına açık, TLS'li, imza doğrulamalı, payload'a güvenmeyen.
- Heartbeat yalnızca şirket içi izleyiciye gider ve içerik taşımaz.
- Yasak: harici hata raporlama/analitik/log servisi (Sentry vb.), CDN'den font/script (tüm statik varlıklar self-host), otomatik güncelleme çağrıları, harici AI/LLM servisi.
- İmaj/bağımlılık indirmeleri yalnızca build sırasında yapılır (indirme yönünde, şirket verisi taşımaz); runtime'da paket yöneticisi çalıştırılmaz. İsteğe bağlı iç registry/mirror kullanılabilir.
- **Doğrulama (zorunlu):** tam bir tarama döngüsü boyunca ağ çıkışı kaydedilir (proxy logu + host firewall logu). Yalnızca allowlist alan adlarına bağlantı kurulduğu ve istek içeriklerinde (URL, header, body) repo/paket adı bulunmadığı otomatik kontrol edilir. Sonuç `docs/EGRESS_REPORT.md`'ye yazılır.

**GitHub erişimi**
- GitHub App (PAT değil). İlk fazda **yalnızca okuma** izinleri; minimum izin kümesini ve Enterprise Server farklarını resmi dokümandan doğrula, `docs/VERIFIED_FACTS.md`'ye yaz. Yazma izni (issue/PR) v1.1'de ayrı App/izinle.
- Private key yalnızca `orchestrator`'da (Docker secret/dosya, 0400). Worker ve app görmez. Kısa ömürlü installation token'ı orchestrator üretir; log'a yazılmaz.
- Git işlemlerinde token'ı **URL'e gömme** (process listesinde/loglarda görünür); geçici http extraheader veya credential helper ile ver. Git sertliği: hook'lar kapalı, submodule recursion yok, LFS smudge kapalı, `GIT_TERMINAL_PROMPT=0`.
- API base URL, App ID, Installation ID konfigüre edilebilir (GHES desteği). Rate limit takibi, retry/exponential backoff, ikincil rate limit (abuse) davranışı.

**Worker izolasyonu**
- `network_mode: none`, read-only root FS, `cap_drop: ALL`, `no-new-privileges`, non-root, varsayılan seccomp profili, CPU/RAM/PID/disk ve job başına timeout limitleri, tmpfs çalışma alanı.
- Repo içeriği **güvenilmeyen girdidir**: hiçbir `install`, build, test, script veya repo kodu çalıştırılmaz; yalnızca statik parse/scan. Scanner çıktısı da güvenilmeyen girdidir (şema doğrulaması, boyut sınırı, ingest'te sanity gate).
- Zafiyet DB'leri ve Gitleaks kuralları worker'a **read-only mount**; indirme/güncelleme orchestrator'da, sürüm+checksum+zaman damgası kaydıyla. Offline çalışma desteklenmiyorsa bunu bana açıkça söyle ve alternatif öner.
- Scanner binary'leri ve imajlar versiyon + digest ile pinli; güncellemeler golden-file + fixture testlerinden geçerek yapılır.

**Uygulama güvenliği**
- **Auth: yerel hesaplar, iki rol.** `admin`: tam yetki (kullanıcı oluşturma/devre dışı bırakma/parola sıfırlama, durum değiştirme, suppression, ayarlar, export, API token'ları). `viewer`: yalnızca görüntüleme (bulgular, paneller, coverage, blast radius); hiçbir yazma uç noktasına erişemez. İlk admin sunucuda CLI ile oluşturulur; admin parolası unutulursa yine sunucuda CLI ile sıfırlanır (RUNBOOK'ta belgele). Parolalar argon2id, minimum uzunluk/karmaşıklık politikası, giriş rate-limit + geçici kilitleme. **Admin için TOTP (2FA) zorunlu** (kurtarma kodlarıyla); viewer için opsiyonel. Oturum çerezi HttpOnly + Secure + SameSite, boşta zaman aşımı, CSRF koruması. **Yetki kontrolü sunucu tarafında**, UI gizlemek yetmez. Viewer tüm repoların bulgularını görür (repo bazlı kapsam v1.1), bu yüzden viewer hesapları yalnızca gerektiği kadar açılır. Admin hesabı tek ve değerli bir ele geçirme noktasıdır (tüm bulguları görür, ayarları değiştirir): THREAT_MODEL'e yazılır, admin sayısı az tutulur, her admin işlemi audit'lenir.
- Scanner çıktısı (paket adı, açıklama, dosya yolu) **güvenilmeyen girdidir**: şablonlarda otomatik escape, `|safe` yok, sıkı CSP, güvenlik header'ları, HTMX'te `allowEval` kapalı.
- **Komut ipucu üretiminde** (ör. `npm install paket@sürüm`) paket adı/sürüm ekosistem kuralına göre **doğrulanmadan** gösterilmez; yalnızca metin olarak gösterilir, otomatik çalıştırılmaz. (Kötü niyetli paket adı `; rm -rf` gibi bir kopyala-yapıştır saldırısına dönüşebilir.)
- Parametreli sorgu/ORM; yol işlemlerinde path traversal koruması.
- Read-only **API token'ları** (hash'li saklanır, scope'lu, süreli, audit'li) — başka ekiplerin "bu CVE bizde var mı" sorgusu için.
- Postgres dışarı açılmaz; yalnızca proxy portu yayınlanır; TLS zorunlu. DB/volume disk şifreleme host seviyesinde (belgele). **Yedekler şifreli** (örn. age/gpg) ve sunucu dışında.
- Secret yönetimi: env/Docker secret; `.env` git'e girmez; pre-commit'te Gitleaks ile kendi repomuzu da tara.
- **Kendi tedarik zincirimiz:** bağımlılıklar hash'li kilitli, minimal base imaj, kendi imajlarımızı ve repomuzu kendi aracımızla tara (dogfooding), SBOM üret.
- Audit log: giriş, durum değişikliği, suppression, kullanıcı/rol/ayar/API-token değişikliği, export.
- **Veri minimizasyonu (KVKK):** kişisel veri yalnızca uygulama kullanıcı hesapları, admin'in girdiği bildirim alıcı adresleri ve işlem kayıtları kadar; commit yazarı adı/e-postası saklanmaz. Mirror önbelleği, ham çıktılar ve audit log için retention config'i.
- `docs/THREAT_MODEL.md`: varlıklar, saldırgan modelleri (kötü niyetli repo içeriği, symlink/zip-bomb tuzakları, çalınmış token/key, ele geçirilmiş worker ve zehirlenmiş sonuç, içeriden kullanıcı, zehirlenmiş advisory/mirror, veri sızdırma: egress, scanner telemetrisi/çevrimiçi sorgular, bulut bildirim kanalları, ele geçirilmiş admin hesabı), kontroller, kalan riskler.

## 6. Özellikler (MVP = bunlar; ek özellik ekleme)

- **A1 Aksiyon grupları (fix-once-close-many):** bulgular CVE'ye değil **aksiyona** göre gruplanır ("paket X → sürüm Y yükseltmesi N repodaki M bulguyu kapatır"), 4.1'deki hesapla; doğrulanmış komut ipucu; toplu gerekçeli işlem.
- **A2 Blast radius:** CVE/paket/sürüm gir → etkilenen tüm repolar ve sahipleri, saniyeler içinde (UI + API). Yeni büyük bir CVE çıktığında ilk sorulan soru budur.
- **A3 Coverage ve sağlık paneli:** taranmayan/dışlanan repolar (gerekçesiyle), lockfile'sız repolar, desteklenmeyen ekosistemler, PARTIAL/başarısız taramalar, tetikleme gecikmesi olan veya rate limit nedeniyle geride kalan repolar, "N gündür doğrulanmadı" repolar, advisory/KEV/EPSS veri yaşı, bilinen kör noktalar (yalnızca default branch taranıyor vb.). Repo bazlı tarama politikası (dahil/hariç + gerekçe, audit'li; arşiv ve fork'lar için varsayılan config).
- **A4 Kanıt paneli:** lockfile yolu/satırı (mümkünse), çözülmüş tam sürüm, advisory affected aralığı, kaynak sayısı/uyumu, skor kaynağı ve çelişkisi, neden Verified / Needs Review, hangi tarama/eşleştirme run'ından.
- **A5 Sahip yönlendirme:** CODEOWNERS → GitHub team/depo eşlemesi (kullanılabilirse) → içe aktarılabilir (CSV) repo→ekip tablosu → "sahipsiz" listesi. Commit yazarı tahmini yok. Sahipsiz bulgular ayrıca görünür.
- **A6 "Bugün" ekranı ve günlük özet:** giriş ekranı aksiyon odaklıdır (bugün yapılacaklar, sahip/ekip filtresi, kullanıcının son ziyaretinden beri yeni olanlar rozetle). Günlük özet (varsayılan iç SMTP, sahip bazlı gönderilebilir; Teams webhook opsiyonel ve yalnızca minimal içerikle, bölüm 5): yeni, kapanan, reopened, başarısız taramalar, KEV'e yeni girenler. **Baseline modu:** bir reponun ilk başarılı taramasındaki bulgular `baseline` etiketlenir; özetler yalnızca baseline sonrası yeni bulguları bildirir, baseline backlog sayısı ayrı gösterilir (config'den kapatılabilir). Bildirimde bulgu başına mesaj yok, konsolide.
- **A7 Önceliklendirme:** 4.6'daki KEV/EPSS tabanlı açıklanabilir sıralama ve görünüm politikası.
- **A8 SLA ve metrik:** severity/KEV'e göre config'den tanımlanan hedef süreler (şirket politikası belirler; kodda sabit rakam yok), `due_date`, gecikenler listesi, günlük metrik snapshot'ı (`daily_metrics`), açık/kapalı trendi ve MTTR.
- **A9 Export ve API:** bulgu listesi/audit için CSV ve JSON export (denetim kanıtı), read-only API (token'lı).
- **A10 Ayarlar ve kullanıcı yönetimi (yalnızca admin):** kullanıcı oluştur/devre dışı bırak/rol ver/parola ve TOTP sıfırla; bildirim kanalları (Teams webhook aç/kapat + URL + test mesajı; e-posta aç/kapat + alıcı listesi; SMTP sunucu parametreleri sunucu config'inde kalır), olay abonelikleri, sessiz saatler, tarama politikası (dahil/hariç repolar, gerekçeli), görünüm politikası (CVSS eşiği, KEV), SLA hedefleri, viewer'lara elle tetikleme izni (varsayılan kapalı, hız limitli). Ayarlar DB'de tutulur, secret içerenler şifreli. Her değişiklik audit'lenir. Egress allowlist'i ve scanner pin'leri bu sayfadan değiştirilemez.
- **Operasyonel (özellik değil, zorunlu):** şirket içi heartbeat (aşağıda), watchdog, şifreli yedek + restore testi.

### İletişim modeli (kullanıcıyla ne zaman ve nasıl konuşuruz)

İlkeler:
1. **Varsayılan sessizlik.** Sistem yalnızca aksiyon gerektiren olayda konuşur. Asıl yüzey paneldir (pull): "Bugün" ekranı ve "son ziyaretinden beri yeni" rozeti. Push (bildirim) yalnızca aşağıdaki olaylarda.
2. **Hız ile gürültü ayrı şeylerdir.** Commit'ler dakikalar içinde görülür (bölüm 3.5'teki hızlı tetikleme + commit sonrası anında eşleştirme), ama bu her commit için mesaj atılacağı anlamına gelmez.
3. Her mesaj şunları taşır: ne oldu, neden önemli, ne yapılmalı (aksiyon), panel bağlantısı. Bulgu başına mesaj yok, konsolide.
4. **Commit anında GitHub'a geri bildirim (PR yorumu, check/status) MVP'de yoktur:** yazma izni gerektirir ve MVP read-only. v1.1'de PR gate (yalnızca PR'ın eklediği yeni zafiyet için). MVP'de bir commit'in getirdiği zafiyet dakikalar içinde panelde ve (kritikse) bildirimle görünür. Commit yazarına kişisel mesaj gönderilmez; bildirimler repo/ekip sahibine ve admin'e gider (KVKK ve kişi bazlı takip riski).
5. Baseline (ilk tarama) bulguları hiçbir zaman bildirim üretmez.

| Olay | Zamanlama | Alıcı |
|---|---|---|
| Commit ile gelen **kritik** bulgu: yeni secret, KEV'de olan veya CVSS ≥ 9 (config) SCA bulgusu (baseline değil) | Anında (tespit gecikmesi + tarama süresi) | Admin + repo sahibi |
| Mevcut bileşende yeni advisory çıktı ve KEV'e girdi / kritik oldu | Hat B senkronundan hemen sonra | Admin + repo sahibi |
| Diğer yeni bulgular, kapananlar, REOPENED | Günlük özet (config saati) | Aboneler |
| SLA yaklaşan / aşılan bulgular | Günlük özet; kritik SLA aşımı admin'e anında | Aboneler, admin |
| Sistem sağlığı: tarama/eşleştirme başarısız, PARTIAL, DB bayat, tetikleme gecikmesi / rate limit bütçesi tükendi | Anında; çözülene kadar günde en çok bir hatırlatma | Admin |
| Haftalık özet: trend, MTTR, kapanan aksiyonlar, kapsam değişimi | Haftada bir | Aboneler |

Kanallar: panel (her zaman), iç SMTP, opsiyonel Teams (yalnızca minimal içerik, bölüm 5). Alıcılar admin'in tanımladığı adresler/dağıtım listeleridir; repo→sahip→alıcı eşlemesi (A5) varsa sahip bazlı ayrı özet gider.

Gürültü kontrolleri: aynı olay aynı alıcıya aynı kanaldan **bir kez** gider (`notification_log` ile idempotent); aynı kontrol döngüsündeki olaylar tek mesajda birleşir; kanal başına saatlik üst limit (aşılırsa tek özet mesajı); sessiz saatler config'den (kritik olaylar hariç); alıcı bazlı olay aboneliği; "kritik" tanımı config'den.

**Dead man's switch (doğru kurulumu):** Sistemin kendi içinde kalan bir alarm, sistem çöktüğünde çalışmaz. Bu yüzden: (1) `watchdog` her döngüde "son başarılı Hat A/Hat B zamanı"nı kontrol edip **şirket içindeki ayrı bir makinede** çalışan bir heartbeat izleyicisine (örn. kendi barındırdığın Uptime Kuma/Healthchecks benzeri; internetteki SaaS izleyiciler kullanılmaz) içerik taşımayan bir ping atar; ping kesilirse alarmı o sistem üretir. (2) Dahili alarm: son başarılı döngü > eşik (config, örn. 36 saat) veya advisory DB bayatsa admin'e iç SMTP ile (ve açıksa Teams minimal mesajıyla) bildirim. (3) Günlük özetin **gelmemesi** de bir sinyaldir; RUNBOOK'ta belgele.

## 7. Aşamalar

**Aşama 0 — Envanter, karar noktası ve doğrulamalar**
- `tools/inventory.py`: okuma yetkili token'ı **ortam değişkeninden** okur; org'daki tüm repoları listeler: visibility, archived/fork, default branch, diller (GitHub languages API), manifest/lockfile varlığı (package-lock.json, yarn.lock, pnpm-lock.yaml, poetry.lock, Pipfile.lock, requirements*.txt, go.mod/go.sum, pom.xml, gradle lockfile, Cargo.lock, composer.lock, Gemfile.lock, *.csproj/packages.lock.json), Dockerfile/compose, CODEOWNERS, Dependabot alert erişimi (yalnızca yanıt kodu), son 30/90 günde commit alan repo sayısı (yoklama bütçesini planlamak için), GitHub API base URL konfigüre edilebilir. Çıktı: `inventory.csv` + özet (ekosistem dağılımı, lockfile'sız repo oranı, tahmini benzersiz bileşen sayısı). Token yazdırılmaz/loglanmaz.
- **Aşama 0b — Matching spike** (`docs/MATCHING_SPIKE.md`): OSV-Scanner'ın güncel dokümanını oku; offline DB, SBOM girdisi, JSON çıktı şeması, yalnızca-envanter çıkarma (varsa) ve ekosistem desteklerini **doğrula**. Bölüm 3.3'teki S1/S2'yi küçük fixture'larla dene (doğruluk, süre) ve **ağsız ortamda gerçekten çalıştığını** doğrula; scanner'ların çevrimiçi/telemetri özelliklerinin nasıl kapatıldığını belgele. Öneriyle raporla. Aynı şekilde Gitleaks (redaction, rapor formatı, commit aralığı), GitHub Trees/Blobs API limitleri, GraphQL toplu HEAD sorgusunun maliyeti ve rate limit bütçesi (60 sn yoklama için), webhook imza/başlık detayları, GHES farkları ve App izin isimleri doğrulanır.
- `docs/DEFECTDOJO_EVAL.md`: DefectDojo'yu Docker ile bir günlük deneme için kontrol listesi (OSV-Scanner/Gitleaks parser'ları, dedup, yaşam döngüsü, CVSS/KEV filtresi, coverage, sahip yönlendirme, SLA ihtiyaçlarımı karşılıyor mu). Bunu **bir insan yapacak**; sen yalnızca listeyi hazırla.
- **DUR.** Envanter sonucunu (özellikle GitHub.com mu GHES mi, aktif repo sayısı ve webhook için gelen bağlantı açmanın mümkün olup olmadığı), spike önerisini ve DefectDojo değerlendirmesini raporla. "Build mi, DefectDojo üstüne ince katman mı" ve eşleştirme stratejisi kararını ben vereceğim. Webhook modülünün (Aşama 2b) açılıp açılmayacağı da bu kapıda benim kararımdır.

**Aşama 1 — İskelet**
Compose iskeleti, Postgres + Alembic, config sistemi, GitHub App auth (installation token), repo discovery, `repositories`, `jobs` (öncelik alanlı) ve `scan_triggers` tabloları (SKIP LOCKED kuyruğu), watchdog iskeleti + heartbeat, healthcheck'ler, JSON loglama (secret maskeleme), `/metrics`. Kabul: boş ve gerçek bir test org'unda repo listesi DB'ye düşer; token loglarda yok; orchestrator kill edilip yeniden başlayınca job'lar kaybolmaz/çift işlenmez.

**Aşama 2 — SCA çekirdeği (Hat A + Hat B)**
tetikleme katmanı (hızlı yoklama, elle tetikleme, debounce, öncelikli kuyruk; bölüm 3.5), Trees/Blobs ile değişiklik tespiti, içerik-adresli önbellek, worker (izole, just-in-time staging), parser/OSV adaptörü, sanity gate, `component_snapshots`, advisory mirror + KEV + EPSS senkronu, benzersiz bileşen eşleştirmesi (günlük tam + commit sonrası anında), Finding modeli, dedup, Verified/Needs Review, patchability ve yükseltme önerisi hesabı, lifecycle + `finding_events`, RESOLVED kuralı, baseline etiketi. Kabul: bölüm 8'deki SCA fixture'ları doğru sonuç verir; hata senaryolarında hiçbir bulgu kapanmaz; commit olmadan yayınlanan yeni advisory ertesi döngüde bulgu üretir; commit→bulgu gecikmesi ölçülüp `docs/PERF.md`'ye yazılır.

**Aşama 2b — Webhook alıcısı (KOŞULLU)**
Yalnızca Aşama 0 raporundan sonra ben açıkça onaylarsam yapılır. `webhook-receiver` servisi (compose profile, varsayılan kapalı), kısıtlı DB rolü, imza/tekrar/boyut/payload'a-güvenmeme testleri, güvenlik duvarı ve RUNBOOK adımları. Kabul: geçersiz imzalı veya sahte istek reddedilir ve hiçbir iş üretmez; geçerli push saniyeler içinde iş üretir; receiver kapalıyken kaçan olay günlük uzlaştırmada yakalanır.

**Aşama 3 — Secret + panel + auth**
Gitleaks adaptörü (redact, fingerprint, incremental, tam-yeniden-tarama tetikleyicileri), secret lifecycle (rotate onayı), FastAPI paneli (repo listesi, bulgu tablosu, filtreler, üzeri çizili resolved), yerel hesaplar + TOTP + admin/viewer RBAC + kullanıcı yönetimi, ayarlar sayfası (A10), audit log, CSRF/CSP, API token'ları. Kabul: ham secret hiçbir yerde görünmez (DB dump, log, API, HTML, bildirim üzerinde otomatik kontrol testi); viewer hiçbir yazma uç noktasına erişemez.

**Aşama 4 — Aksiyon katmanı**
A1–A9 ve iletişim modeli (olay tablosu, abonelikler, gürültü kontrolleri, `notification_log`), bildirimler (konsolide, sahip bazlı), SLA, CSV/JSON export, Coverage ve "Bugün" ekranları. Kabul: fixture verisiyle gruplama, blast radius, coverage, baseline davranışı ve günlük özet doğru üretilir.

**Aşama 5 — Operasyon ve kalite**
Şifreli günlük `pg_dump` + retention + **restore testi**, scanner/DB pinleme ve kontrollü güncelleme prosedürü, `RUNBOOK.md` (kurulum, GitHub App kurulumu, ilk admin oluşturma ve parola/TOTP sıfırlama, egress allowlist yönetimi, yedek/restore, güncelleme, sorun giderme, heartbeat kurulumu), `THREAT_MODEL.md`, `LIMITATIONS.md` (bilinen kör noktalar), `PERF.md`, precision/recall raporu, uçtan uca duman testi (compose up → tarama → panel), **24 saat kesintisiz çalışma denemesi**, **egress doğrulama raporu** (bölüm 5).

## 8. Test planı

**Fixture repoları** (küçük, lokal/test org'unda; gerçek şirket kodu kullanma):
1. Temiz repo (gürültü üretmemeli)
2. Doğrudan zafiyetli bağımlılık (CVSS ≥ 7)
3. Geçişli (transitive) zafiyetli bağımlılık
4. Önce zafiyetli sonra yükseltilmiş repo (RESOLVED doğrulaması)
5. Fix'i olmayan zafiyet (`NO_FIX_YET`/`FIX_UNKNOWN`)
6. Lockfile'sız manifest (Verified olmamalı, Coverage'da görünmeli)
7. Sahte (gerçek olmayan) secret içeren repo; secret sonradan silinse bile bulgu kapanmamalı
8. Affected aralığın hemen altı / içi / fix ve sonrası sürümler
9. Aynı advisory'nin CVE/GHSA/OSV çoklu kimliği (dedup)
10. **HEAD değişti ama hiçbir lockfile blob'u değişmedi** (yeniden çıkarma yapılmamalı)
11. **Kod değişmeden yeni advisory yayınlandı** (yerel mirror'a test advisory enjekte et; ertesi Hat B'de yeni bulgu çıkmalı)
12. **Advisory geri çekildi** (gerekçeli RESOLVED)
13. Force-push / geçmiş yeniden yazımı (secret için tam yeniden tarama tetiklenmeli)
14. Monorepo: çok lockfile, biri parse edilemez (yalnızca o PARTIAL; diğerleri normal)
15. KEV'de olup CVSS'i düşük/yok bulgu (görünüm politikası ve sıralama)
16. **Commit ile eklenen zafiyetli bağımlılık** (hedef gecikme içinde bulgu çıkmalı; kritikse anında bildirim, değilse günlük özet)
17. **Aynı repoya arka arkaya 5 push** (tek işe birleşmeli, son SHA işlenmeli, ara commit'lerdeki secret kaçmamalı)
18. **Tetikleyici kaçırıldı** (yoklama durdurulup commit atılır; günlük uzlaştırma yakalamalı)
19. **Düşük rate limit bütçesi** (kuyruk geri çekilmeli, gecikme panelde ve sağlık bildiriminde görünmeli, hiçbir bulgu kapanmamalı)
20. **Elle tetikleme** (aynı SHA için fazladan iş üretmemeli; viewer izni kapalıyken reddedilmeli)
21. (Yalnızca webhook modülü açıksa) geçersiz imza, tekrar eden delivery, aşırı büyük gövde, payload'daki SHA'nın gerçek SHA'dan farklı olması

**Hata ve saldırı senaryoları:** parse hatası, clone/GitHub erişim hatası, timeout, worker çökmesi, **boş/eksik/zehirlenmiş worker sonucu** (sanity gate: hiçbir bulgu kapanmamalı), bileşen sayısında ani çöküş, bayat advisory DB, KEV/EPSS senkron hatası, **symlink tuzağı** (lockfile → `/run/secrets/...`), çok büyük lockfile/zip-bomb, orchestrator yeniden başlatma, orchestrator durdurulunca watchdog/heartbeat alarmı. Hepsinde hiçbir bulgu yanlışlıkla RESOLVED olmamalı.

**Kalite ölçümü:** fixture setinde TP/FP/FN sayımı, precision = TP/(TP+FP), recall = TP/(TP+FN), duplicate oranı, tarama/eşleştirme süresi ve kaynak kullanımı, önbellek isabet oranı. Sadece FP düşsün diye aşırı filtreleme yapma; recall'u birlikte raporla. İnsan tarafından çalıştırılan `tools/dependabot_compare.py` (okuma yetkili token ortam değişkeninden): Dependabot alert'lerini aracımızın bulgularıyla karşılaştırıp **kaçırdığımız bulguları (recall)** ve çelişkileri raporlar; Dependabot burada yalnızca bağımsız doğrulama kaynağıdır, ürün akışına girmez (App'e ek izin gerektirmez). Hedef eşikleri PoC sonrası birlikte belirleyeceğiz.

**Güvenlik testleri:** worker'ın gerçekten network'süz olduğunu doğrulayan test; **egress testi** (tam döngüde yalnızca allowlist alan adlarına bağlantı, istek içeriğinde repo/paket adı yok; scanner'lar için telemetri/çevrimiçi sorgu denemesi yok); bildirimlerin `minimal` düzeyde bulut kanallarına ayrıntı sızdırmadığını doğrulayan test; ham secret sızıntı testi (DB/log/API/HTML/bildirim); XSS payload'lı paket adı fixture'ı; komut ipucunda kötü niyetli paket adı; path traversal; RBAC testleri (viewer hiçbir yazma uç noktasına erişemez, doğrudan istek dahil); yetkisiz suppression; CSRF; parola politikası, kilitleme ve TOTP akışı; Teams webhook URL'sinin arayüzde/logda/API'de görünmediğini doğrulayan test; bildirim idempotency ve hız limiti testleri; API token scope/süre testleri; adaptör golden-file testleri.

## 9. Teslim edilecekler

Çalışan `docker compose up` ile ayağa kalkan sistem, tüm testler (pytest) ve CI'da çalışacak komutları, `README.md` (hızlı başlangıç), `docs/` altındaki belgeler (VERIFIED_FACTS, ASSUMPTIONS, THREAT_MODEL, RUNBOOK, DEFECTDOJO_EVAL, MATCHING_SPIKE, PERF, LIMITATIONS, EGRESS_REPORT), bilinen sınırlamalar ve doğrulanamayan varsayımlar listesi.

## 10. Şimdi ne yapacaksın

1. Bu belgeyi baştan sona oku. Belirsiz bir nokta varsa **en fazla 3 kısa soru** sor; yoksa sorma.
2. Görev listesini oluştur ve **Aşama 0 / 0b**'den başla. Bitince dur ve raporla.
3. Ben "devam" demeden Aşama 1'e geçme.
