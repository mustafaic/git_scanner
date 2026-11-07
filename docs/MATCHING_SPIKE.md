# MATCHING_SPIKE.md (Aşama 0b)

**Amaç:** master_prompt.md §3.3'teki S1 (SBOM → OSV-Scanner offline) ve S2
(lockfile blob → OSV-Scanner offline) stratejilerini küçük fixture'larla
**gerçekten çalıştırıp** doğruluk/süre/offline-çalışabilme kriterlerine göre
karşılaştırmak ve bir öneri sunmak.

**Test ortamı:** `google/osv-scanner` v2.7.0 (resmi GitHub release, Windows
amd64 binary), 2026-11-08. Gerçek şirket verisi KULLANILMADI — tüm
fixture'lar bu oturumda elle oluşturulan sahte/örnek verilerdir (lodash
4.17.15, gin-gonic/gin v1.6.3 — herkese açık, bilinen zafiyetli sürümler).
Testler bu makinede (şirket ağı dışında, izole) çalıştırıldı.

## 1. Offline çalışma — ampirik doğrulama (iddia değil, test edildi)

Yöntem: `HTTP_PROXY`/`HTTPS_PROXY`'yi çözümlenemez bir adrese
(`http://127.0.0.1:1`) ayarlayıp taramayı tekrar çalıştırdım. Eğer araç
gizlice ağa çıkmaya çalışsaydı bağlantı anında reddedilip hata/timeout
verirdi. Her iki senaryoda (normal ortam / kırık proxy) **aynı sonuç, aynı
sürede** üretildi → gerçek bir ağsız çalışma kanıtı (sadece dokümana
güvenmedim).

```
osv-scanner scan source --offline --format json -L fixture/package-lock.json
```
- Kırık proxy ile: ✅ başarılı, 1 paket (lodash@4.17.15), **5 vulnerability**
  (GHSA-29mw-wpgm-hmr9, GHSA-35jh-r3h4-6jhm, GHSA-p6mc-m468-83gw,
  GHSA-r5fr-rjxr-66jc, GHSA-xxjr-mmjv-4gpg) — sonuç normal ortamla **bit bit
  aynı**.

**Sonuç:** `--offline` (DB önceden `--download-offline-databases` ile
indirilmiş olmak kaydıyla) gerçekten ağsızdır. master_prompt.md §5'in
"varsayılanın çevrimiçi olabileceğini varsay" uyarısı **doğru** çıktı
(bkz. VERIFIED_FACTS.md — varsayılan mod `--data-source=deps.dev` ile
çevrimiçidir); üretimde **her çalıştırmada açıkça `--offline` geçilmeli**,
asla varsayılana güvenilmemeli.

## 2. S2 — Lockfile tabanlı (package-lock.json, go.mod)

- **npm:** `fixture/package-lock.json` (lodash@4.17.15) → 5 doğru bilinen
  CVE/GHSA bulundu, JSON'da `affected[].ranges[].events` içinde
  `introduced`/`fixed` alanları var (patchability hesabı için gerekli ham
  veri bu).
- **Go:** `fixture_go/go.mod` (`github.com/gin-gonic/gin v1.6.3`) → 5
  vulnerability bulundu. **go.mod doğrudan "lockfile" tipi olarak tanındı**
  (go.sum'a gerek yok) — VERIFIED_FACTS.md madde 8'deki düzeltmeyi
  doğruluyor. Not: `call-analysis` (govulncheck) adımı Go toolchain
  olmadığı için "failed" uyarısı verdi ama bu **opsiyonel/deneysel** bir
  özellik (varsayılan açık değil, `--call-analysis=go` ile açılır);
  temel lockfile taraması bundan etkilenmedi.
- Monorepo/çoklu-lockfile senaryosu (master_prompt §3.2.8: "lockfile
  bazında" bağımsız başarı/başarısızlık) bu spike'ta ayrıca test
  edilmedi — tek-lockfile fixture'larla sınırlı kaldı; Aşama 2'de gerçek
  monorepo fixture'ıyla (bkz. §8 test planı madde 14) doğrulanacak.

## 3. S1 — SBOM tabanlı (CycloneDX)

- Minimal CycloneDX 1.5 SBOM (`{"components":[{"name":"lodash",
  "version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"}]}`) `--offline`
  modda, kırık proxy ile verildi → **aynı 5 vulnerability**, kırık proxy
  altında da başarılı.
- **Önemli doküman notu:** `--sbom`/`-S` flag'i v2.7.0'da **DEPRECATED**;
  SBOM dosyası artık dizin taraması (`scan source <dir>`) sırasında
  dosya içeriğinden otomatik algılanıyor (plugin sistemi, `--x-plugins`).
  Bu, resmi dokümanın (offline-mode sayfası) SBOM'dan bahsetmemesinin
  nedeni olabilir — SBOM artık ayrı bir "mod" değil, genel dosya
  algılamasının bir parçası. **ASSUMPTIONS.md madde 1 bu testle
  ÇÖZÜLDÜ: S1 de `--offline` ile tam çalışıyor.**

## 4. JSON çıktı şeması (her iki strateji için aynı)

```
{
  "results": [
    {
      "source": {"path": "...", "type": "lockfile" | "sbom"},
      "packages": [
        {
          "package": {"name", "version", "ecosystem", "purl"},
          "groups": [{"ids": [...], "aliases": [...], "max_severity": "..."}],
          "vulnerabilities": [
            {
              "id": "GHSA-...", "aliases": ["CVE-..."], "summary", "details",
              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."}],
              "affected": [{"package": {...}, "ranges": [{"type": "SEMVER",
                  "events": [{"introduced": "x"}, {"fixed": "y"}]}],
                  "database_specific": {...}}],
              "database_specific": {"severity": "HIGH", "cwe_ids": [...]}
            }
          ]
        }
      ]
    }
  ]
}
```

**S1 ve S2 çıktı şeması BİT BİT AYNI** (`package/groups/vulnerabilities`
yapısı ikisinde de identik). Bu, hangi strateji seçilirse seçilsin ingest/
normalize katmanının (master_prompt.md §3.4 adaptör arayüzü) **tek bir**
parser ile yazılabileceği anlamına geliyor.

**Önemli boşluk — Aşama 2'de ele alınmalı:** `severity[].score` CVSS
**vektör string**'idir (`CVSS:3.1/AV:N/...`), **sayısal skor değil**.
master_prompt.md §1 ve §6 (CVSS≥7.0 görünüm politikası) sayısal skor
gerektiriyor. İki seçenek: (a) `database_specific.severity` (LOW/MEDIUM/
HIGH/CRITICAL gibi kaba etiket) kullan, (b) CVSS vektöründen taban skoru
hesapla (CVSS v3.1 formülü kamuya açık, saf fonksiyon olarak yazılabilir
veya olgun bir kütüphaneyle — kural 3 gereği sıfırdan "skorlama motoru"
değil, tek, iyi test edilmiş bir formül hesaplayıcısı). **Öneri: (b)** —
kaba etiket CVSS eşiğini (≥7.0) doğru temsil etmeyebilir (örn. "HIGH"
etiketi CVSS 7.0-8.9 aralığına denk gelir ama kesin değildir).

## 5. Disk/performans gözlemleri (Aşama 2'de ölçülüp docs/PERF.md'ye taşınacak)

- Offline DB boyutu (bu spike'ta indirilen): **npm ~210 MB**, **Go ~13 MB**
  (ekosisteme göre değişir — tüm ekosistemler indirilirse mirror disk
  ihtiyacı birkaç GB olabilir, kapasite planlamasında not edilmeli).
- Her CLI çalıştırması DB zip'ini **yeniden yüklüyor** (`Loaded npm local
  db from .../all.zip` her seferinde log'da çıktı) — kalıcı bir daemon/
  süreç yok. Tek dosya/tek repo için ilk çalıştırma ~17s (DB indirme
  dahil), DB cache'lenmişken ~10s. Bu, §3.5'teki "commit sonrası anında
  eşleştirme" hedefi (dakikalar içinde) için **yeterli** görünüyor ama
  yüksek-frekanslı tetikleyici fırtınasında (çok sayıda ardışık commit)
  her job için DB'nin yeniden yüklenme maliyeti Aşama 2'de gerçek ölçekte
  ölçülmeli (kural 11: ölç, sonra optimize et).

## 6. Öneri

**S2 (lockfile blob → OSV-Scanner offline) birincil strateji olarak
seçilsin.**

Gerekçe:
1. Hat A zaten her repo için değişen lockfile blob'larını indiriyor
   (§3.2) — bu blob'u doğrudan osv-scanner'a vermek, ayrıca bir SBOM
   üretim adımı eklemekten daha basittir (kural 11).
2. master_prompt §3.2.8'in "lockfile bazında bağımsız başarı/başarısızlık"
   gereksinimi, doğal olarak lockfile-başına ayrı `osv-scanner` çağrısıyla
   karşılanır; SBOM'da tüm bileşenler tek dosyada birleşirse bu ayrım
   kaybolabilir.
3. S1 ile S2'nin çıktı şeması bit bit aynı olduğu için bu seçim gelecekte
   (ör. CycloneDX export özelliği devreye girince, v1.1) **S1'e geçişi
   ucuz** bırakıyor — tek parser iki girdi tipini de okuyabilir.

**S1, şimdilik kullanılmıyor ama şeması doğrulandığı için v1.1'deki
CycloneDX/VEX export özelliği (§2) geldiğinde aynı altyapı export
tarafında yeniden kullanılabilir.**

## 7. Doğrulanan/doğrulanamayan özet

| Soru | Durum |
|---|---|
| Offline çalışma gerçek mi (sadece dokümana güvenme, test et)? | **AMPİRİK DOĞRULANDI** (kırık proxy testi) |
| SBOM + offline birlikte çalışıyor mu? | **AMPİRİK DOĞRULANDI** (ASSUMPTIONS.md madde 1 çözüldü) |
| go.mod lockfile olarak tanınıyor mu? | **AMPİRİK DOĞRULANDI** |
| S1/S2 JSON şeması aynı mı? | **AMPİRİK DOĞRULANDI** (identik) |
| CVSS sayısal skor doğrudan geliyor mu? | **HAYIR** — vektörden hesaplanmalı (yeni bulgu, Aşama 2 tasarımına girdi) |
| Monorepo/çoklu-lockfile bağımsız hata izolasyonu | **TEST EDİLMEDİ** (Aşama 2 fixture'ında yapılacak) |
| pom.xml gerçek "resolved" sürüm üretiyor mu (offline)? | **TEST EDİLMEDİ** — ASSUMPTIONS.md madde 5'te açık kaldı |
