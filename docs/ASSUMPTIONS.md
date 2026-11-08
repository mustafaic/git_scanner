# ASSUMPTIONS.md

Doğrulanamayan veya kısmi doğrulanan noktalar (master_prompt.md kural 2).
Her biri Aşama 1+ sırasında gerçek org/gerçek araçla netleştirilmeli.

## 1. ~~OSV-Scanner: SBOM girdisi + `--offline` kombinasyonu~~ — ÇÖZÜLDÜ

**Çözüldü (2026-11-08, bkz. docs/MATCHING_SPIKE.md §3):** Gerçek
`osv-scanner` v2.7.0 binary'si indirilip, kırık/çözümlenemez bir proxy
ile (`HTTP_PROXY=http://127.0.0.1:1`) minimal bir CycloneDX SBOM fixture'ı
üzerinde çalıştırıldı; sonuç başarılı ve DB-cache'li normal çalıştırmayla
bit bit aynıydı → SBOM girdisi de gerçekten offline çalışıyor. Ayrıca
`--sbom` flag'inin v2.7.0'da deprecated olduğu, SBOM dosyalarının artık
dizin taramasında otomatik algılandığı görüldü.

## 2. Gitleaks: varsayılan telemetri/ağ çağrısı yokluğu

**Varsayım:** Gitleaks'in hiçbir varsayılan ağ çağrısı/telemetrisi yok.

**Neden doğrulanamadı:** README'de konu hiç geçmiyor (ne "vardır" ne
"yoktur" deniyor). Mimari olarak yerel `git log` çıktısını parse ettiği
için tasarım gereği ağ bağımlılığı olmaması mantıklı, ama vendor'dan açık
bir beyan yok.

**Nasıl netleştirilir:** Worker zaten `network_mode: none` olacağı için
ürün güvenliği açısından risk düşük (ikinci güvence katmanı), ama
**egress doğrulama testinde** (bölüm 5, "Doğrulama zorunlu") Gitleaks
çalıştırması sırasında da sıfır dış bağlantı gözlemlenerek ampirik olarak
doğrulanacak.

## 3. Gitleaks fingerprint kararsızlığı — KARAR VERİLDİ (2026-11-08)

**Kullanıcı kararı:** Seçenek (b) — kendi ikincil fingerprint'imizi
hesaplayacağız: `rule ID + dosya yolu + secret-content hash` (satır
numarasından bağımsız). Gitleaks'in orijinal (satır-bağımlı) fingerprint'i
kanıt/referans olarak saklanacak ama dedup anahtarı olarak KULLANILMAYACAK.
Bu, Aşama 3 (Secret + panel + auth) tasarımına girdi olarak işlenecek.

**Doğrulanmış çatışma (bkz. VERIFIED_FACTS.md):** Gitleaks'in kendi
fingerprint'i (`commitSHA:path:ruleID:line`) satır numarası değişince
değişir. master_prompt.md 4.4 ise "fingerprint kararlı olmalı, satır
kayınca yeni bulgu doğmasın" diyor.

**Seçenekler (kullanıcı ile Aşama 3 tasarımında netleştirilecek):**
- (a) Gitleaks fingerprint'ini olduğu gibi kullan, satır kayması = yeni
  bulgu kabul et (basit ama gürültü riski: aynı secret'ın üstüne bir satır
  eklenince "yeni" görünür).
  (b) Kendi ikincil fingerprint'imizi hesapla: `rule ID + dosya yolu +
  secret-content hash` (satırdan bağımsız) — Gitleaks'in orijinal
  fingerprint'ini kanıt olarak sakla, dedup anahtarı olarak kendi
  hesabımızı kullan.
- (c) Hibrit: content-hash eşleşirse aynı bulgu kabul et, satır/commit
  bilgisini sadece "son görülen konum" olarak güncelle.

**Öneri:** (b) — master_prompt.md'nin kararlılık gereksinimini gerçekten
karşılayan tek seçenek bu. Ama bu bir **ek parse/hash adımı** demek,
yazılı gerekçeyle Aşama 3'te kullanıcıya sunulacak (kural 11).

## 4. GraphQL batch sorgu point maliyeti (60 sn yoklama bütçesi)

**Varsayım:** `repository(owner,name){defaultBranchRef{target{oid}}}`
şeklinde çok-repo batch sorgusunun saatlik 5.000-12.500 point bütçesi
içinde rahatça sığacağı varsayılıyor (bölüm 3.5.1).

**Neden doğrulanamadı:** Resmi dokümanda alan-bazlı tam point maliyet
tablosu yok (genel ilke var, kesin sayı yok).

**Nasıl netleştirilir:** Aşama 1/2'de gerçek org ile ölçülüp
`docs/PERF.md`'ye yazılacak; bütçe yetersizse bölüm 3.5.1'deki
sıcak/soğuk katmanlama uygulanacak (kural 11: ölç, sonra optimize et).

## 5. pom.xml / Maven: lockfile mi, manifest-only mi?

**Karar (temkinli taraf):** `tools/inventory.py` pom.xml'i şu an
`manifest_only` sayıyor (Verified olamaz, UNVERIFIED_NO_LOCKFILE).

**Neden belirsiz:** OSV-Scanner resmi olarak pom.xml'i doğrudan
okuyabiliyor (VERIFIED_FACTS.md madde 8), ama Maven'da sürüm aralıkları/
property placeholder'ları yaygın ve gerçek transitive resolution normalde
Maven'ın kendi resolver'ını (ve çoğunlukla Maven Central'a ağ erişimini)
gerektirir. OSV-Scanner'ın pom.xml'den ürettiği "resolved version"ın
şirketin **offline** ortamında ne kadar güvenilir olduğu doğrulanmadı.

**Nasıl netleştirilir:** Aşama 0b fixture testinde gerçek bir Maven
projesiyle `--offline` modda denenip çıkan sürümlerin doğruluğu elle
kontrol edilecek; sonuca göre pom.xml lockfile sayılabilir veya
`manifest_only` olarak kalır (kullanıcı onayı ile).

## 6. pnpm-lock.yaml bileşen sayısı tahmini yok

**Karar:** `tools/inventory.py`'de pnpm-lock.yaml ecosystem olarak
**tespit ediliyor** (lockfile sinyali doğru) ama kaba bileşen sayısı
**tahmin edilmiyor** çünkü Python stdlib'de YAML parser yok ve Aşama 0'da
ek bağımlılık eklenmiyor (kural 11). Bu sadece envanter scriptinin
"tahmini" özetini etkiler, ürünün gerçek eşleştirme motorunu (Aşama 2 Hat
B, OSV-Scanner kendisi) etkilemez — OSV-Scanner pnpm-lock.yaml'ı zaten
native destekliyor.

## 7. GHES `/meta` endpoint IP aralığı davranışı

**Varsayım:** Webhook modülü (Aşama 2b, koşullu) GHES üzerinde
kullanılırsa, trafik şirket içi ağda kalacağı için GitHub.com'un dinamik
IP aralığı sorunu daha az kritik olacağı varsayılıyor.

**Neden doğrulanamadı:** GHES'in kendi `/meta` endpoint'inin davranışı
(veya bu senaryoda hiç gerekip gerekmediği) ayrıca doğrulanmadı — bu
yalnızca Aşama 2b onaylanırsa ve GHES kullanılıyorsa gündeme gelir.

## 8. İlk admin GitHub kullanıcısının token/App kurulum detayları

master_prompt.md §5 "GitHub erişimi" bölümündeki GitHub App minimum izin
isimleri (Contents: Read-only, Metadata: Read-only, Dependabot alerts:
Read-only) VERIFIED_FACTS.md'de doğrulandı; ancak **App'in organizasyona
kurulumu (installation) adımının tam ekran akışı** ve **GHES'te App
kaydının farklı bir admin onay akışı gerektirip gerektirmediği**
doğrulanmadı — bu, Aşama 1'de gerçek bir test org'unda elle kurulum
yapılırken netleşecek ve RUNBOOK.md'ye yazılacak.

## 10. Cargo (Rust) için univers Version sınıfı: SemverVersion fallback

**Varsayım:** `univers` kütüphanesinde Cargo'ya özel bir Version sınıfı
bulunamadı (bkz. VERIFIED_FACTS.md madde 6). `core/finding_model.py`
Cargo/crates.io ekosistemi için `SemverVersion`'ı kullanıyor (Rust crates
standart semver kullanır).

**Nasıl netleştirilir:** Gerçek bir Cargo.lock fixture'ıyla (bilinen
zafiyetli bir Rust crate) Aşama 2 fixture testlerinde doğrulanacak; semver
karşılaştırması yanlış sonuç verirse `FIX_UNKNOWN` fallback'i zaten devrede
(kural: güvenilir hesaplanamıyorsa öneri üretilmez).

## 9. ~~CVSS sayısal skor: OSV-Scanner çıktısında doğrudan yok~~ — ÇÖZÜLDÜ

**Çözüldü (2026-11-08):** `severity[].score` bir **CVSS vektör string**'i
(`CVSS:3.1/AV:N/...`), sayısal taban skoru değil. Python `cvss` kütüphanesi
(v3.6) bu vektörü doğrudan kabul ediyor ve taban skoru hesaplıyor (host'ta
smoke-test edildi, bkz. VERIFIED_FACTS.md madde 7). `core/finding_model.py`
bunu kullanıyor; parse edilemezse `database_specific.severity` kaba
etiketine (LOW/MEDIUM/HIGH/CRITICAL) düşer ve bu durumu `severity_source`
alanında işaretler.

## 11. Viewer rolü ve API token self-servisi — KARAR VERİLDİ (2026-11-08)

**Çatışma:** master_prompt.md 7 (Aşama 3 kabul kriteri): "viewer hiçbir
yazma uç noktasına erişemez (doğrudan istek dahil)". Panelde ise her
kullanıcı (viewer dahil) kendi read-only API token'ını oluşturup iptal
edebiliyor (`POST /tokens`, `POST /tokens/{id}/revoke`) -- bu teknik
olarak bir yazma işlemi.

**Kullanıcı kararı:** Viewer'a izin verilsin (mevcut davranış korundu).
Gerekçe: viewer kendi için ürettiği bir read-only-scope token ile API
üzerinden çekebileceği veri, panelde zaten görebildiği veriyle AYNI --
gerçek bir yetki yükselmesi değil, sadece erişim kanalı değişiyor. Bu,
"viewer hiçbir yazma uç noktasına erişemez" kuralının **TEK istisnası**
olarak kabul edildi.

**Uygulama:** `app/routes_tokens.py` (`require_user`, admin değil) +
`tests/integration/test_app_panel_postgres.py::test_viewer_can_only_reach_own_token_write_endpoints_all_other_writes_blocked`
bu istisnayı ve TÜM diğer yazma uç noktalarının (bulgu durumu, secret
rotasyonu, elle tetikleme, audit log görüntüleme) viewer için 403 ile
reddedildiğini doğrular.

## 12. A10 kullanıcı yönetimi paneli: admin oluşturma ve TOTP sıfırlama kapsam dışı (2026-11-08)

**Karar:** master_prompt.md 6 (A10) "kullanıcı oluştur/devre dışı bırak/rol
ver/parola ve TOTP sıfırla" özelliğini panelden (`/users`) sadece
**viewer** hesapları için uyguladık: oluşturma, aktif/pasif, parola
sıfırlama. Yeni bir **admin** hesabı oluşturmak ve TOTP sıfırlamak
(herhangi bir rol için) panelden YAPILAMAZ, `tools/create_admin.py`
(sunucu CLI) gerektirir.

**Gerekçe:** Her iki işlem de bir "sır paylaşma seremonisi" içerir (TOTP
secret/provisioning URI + tek-seferlik kurtarma kodları) ve bunu web
üzerinden güvenli şekilde iletecek bir dışarıdan-kanal yok -- admin'in
ekranında beliren bir sırrı başka bir kullanıcıya web üzerinden
göstermenin kendisi bir sızıntı riski. CLI zaten sunucuya fiziksel/SSH
erişimi olan birinin çalıştırdığı, doğal olarak güvenli bir kanaldır
(mevcut "ilk admin CLI ile oluşturulur" kuralıyla simetrik).

**Yeniden değerlendirme noktası:** Panelden admin oluşturma gerekirse,
QR kod render'ı (`qrcode` paketi, yeni bağımlılık) + bir "TOTP kurulumu
bekleniyor" ara durumu (yeni kullanıcı ilk girişte zorla TOTP enroll
eder) gerekir -- bu Aşama 4/5'te ayrıca değerlendirilebilir, şu an MVP
kapsamı dışında tutuldu (kural 11).

## 13. A5 sahip yönlendirme: CODEOWNERS otomatik tespiti kapsam dışı (2026-11-09)

**Karar:** master_prompt.md 6 (A5) sıralaması "CODEOWNERS → GitHub
team/depo eşlemesi (kullanılabilirse) → içe aktarılabilir (CSV) → 'sahipsiz'
listesi" şeklinde. Bu turda SADECE CSV import uygulandı (`app/routes_owners.py`,
`core/owners.py`); CODEOWNERS'ın otomatik okunup parse edilmesi YAPILMADI.

**Gerekçe:** CODEOWNERS tespiti, orchestrator'ın extraction akışına YENİ bir
GitHub API çağrısı (tree'de `.github/CODEOWNERS`/`CODEOWNERS`/`docs/CODEOWNERS`
arama + blob fetch + parse) eklemeyi gerektiriyor -- bu, zaten test edilmiş
Hat A kodunu (orchestrator/extraction.py) genişletmek anlamına gelir ve
gerçek bir test org'unda CODEOWNERS içeren bir repo olmadan ampirik
doğrulanamaz. CSV import, aynı nihai durumu (repo → sahip eşlemesi) sıfır
orchestrator riskiyle sağlıyor.

**Şema hazır:** `repo_owners.source` sütunu `'codeowners'` değerini zaten
kabul ediyor (CheckConstraint) -- CODEOWNERS desteği eklenince şema
değişikliği GEREKMEYECEK, sadece orchestrator'a bir senkron adımı eklenecek.

