# PERF.md — Aşama 2 performans ölçümleri

Bu ölçümler **gerçek bir GitHub hesabına karşı** (23 repo, App ID 5661812),
gerçek OSV-Scanner v2.7.0 binary'si ve gerçek offline advisory DB'lerle
(KEV, EPSS, 8 ekosistem) canlı `docker compose` stack'inde yapılmıştır
(2026-11-08). Sentetik benchmark değil.

## 1. Mirror senkronu (günlük, tek seferlik maliyet)

| Kaynak | Boyut/kayıt sayısı | Not |
|---|---|---|
| osv-npm | 220 052 609 bayt (~210 MB) | En büyük ekosistem DB'si |
| osv-PyPI | 37 666 406 bayt (~36 MB) | |
| osv-Go | 12 828 902 bayt (~13 MB) | |
| osv-Packagist | 11 107 565 bayt | |
| osv-Maven | 10 527 068 bayt | |
| osv-crates.io | 3 799 768 bayt | |
| osv-RubyGems | 5 213 495 bayt | |
| osv-NuGet | 2 697 117 bayt | |
| KEV | 1 769 kayıt | GitHub mirror (cisagov/kev-data) üzerinden — doğrudan cisa.gov 403 döndürüyor |
| EPSS | 401 675 kayıt | |

**Toplam süre (8 ekosistem + KEV + EPSS, sıralı indirme + SHA256 doğrulama + CSV parse):
~3 dakika.** Baskın maliyet npm DB'sinin indirilmesi + checksum hesaplanması.

**Bilinen iyileştirme fırsatı (ölçüldü, henüz uygulanmadı — kural 11: ölç,
sonra optimize et):** Şu an tüm mirror senkronu TEK bir DB transaction'ı
içinde yapılıyor (`orchestrator/main.py::_run_daily_jobs`), yani ~3 dakika
boyunca tek bir DB bağlantısı açık kalıyor. Gerçek ölçekte (çok sayıda eş
zamanlı bağlantı varsa) ekosistem başına ayrı transaction'a bölünmesi
düşünülebilir. Şu an tek-orchestrator senaryosunda sorun gözlenmedi.

## 2. Hat A (envanter çıkarma) + anlık Hat B (eşleştirme) — repo başına

| Repo | Lockfile | Bileşen sayısı | Gözlenen süre (tetikleyici → bulgu DB'de) |
|---|---|---|---|
| mustafaic/Nexus | go.mod | 1 | ~10 sn (elle tetikleme → extraction → immediate match tamamlandı) |
| mustafaic/ai_scan | frontend/package-lock.json | 989 | ~12.7 sn (blob indirme + worker parse + worker osv-scan + ingest) |
| lockfile'sız repolar (18 repo) | — | 0 | ~1 sn (tree çekildi, lockfile bulunamadı, iş tamamlandı) |

**Sonuç:** Bileşen sayısı arttıkça süre lineer-altı büyüyor (worker'ın tek
osv-scanner çağrısı tüm bileşenleri aynı anda işliyor; darboğaz GitHub API
round-trip'leri ve tek worker instance'ının seri işleme sırası).

## 3. Uçtan uca commit → bulgu gecikmesi (hedef: master_prompt.md 3.5.4)

Gerçek bir commit ile ölçüm bu oturumda yapılmadı (kullanıcının gerçek
reposuna test commit'i atmak onay gerektirir). Bunun yerine **ölçülen alt
bileşenlerden teorik üst sınır** hesaplanmıştır:

```
hızlı yoklama gecikmesi      : 0-60 sn  (POLL_INTERVAL_SECONDS, varsayılan 60)
debounce penceresi           : 0-20 sn  (DEBOUNCE_WINDOW_SECONDS, varsayılan 20)
claim loop tick               : 0-2 sn   (CLAIM_LOOP_INTERVAL_SECONDS, varsayılan 2)
Hat A + anlık Hat B           : 1-15 sn  (olcum: bolum 2, repo buyuklugune gore)
---------------------------------------------------------------
TOPLAM (tipik)                 : ~30-90 saniye, en kötü durum ~150 sn
```

Bu, master_prompt.md 3.5.4'teki "yoklama modunda birkaç dakika" hedef
taslağının **içinde**. `commit_to_finding_seconds` ve `trigger_detection_seconds`
metrikleri `/metrics`'e henüz eklenmedi (Aşama 4'te A8/SLA ile birlikte
gerçek commit testiyle doğrulanacak; `docs/LIMITATIONS.md` Aşama 5'te
yazılacak, bilinen sınırlama olarak bu belgede işaretli kalacak).

## 4. Gerçek bulgu doğruluğu (yan ürün — doğruluk kanıtı)

Canlı taramada bulunan gerçek örnek: `mustafaic/ai_scan`'daki
`brace-expansion@5.0.5` için 7 farklı GHSA ID, her biri doğru CVSS skoru ve
**o vulnerability'ye özel** doğru fix_version önerisiyle (5.0.6 — 5.0.12
arası, en küçük düzeltme sürümü her biri için ayrı hesaplandı, kural: 4.1).
Toplam: **990 bileşen, 4 repo, 231 gerçek bulgu** (hiçbiri sentetik fixture
değil).

## 5. Worker izolasyonu — ek bulgu (düzeltildi)

Canlı testte **gerçek bir bug** bulundu ve düzeltildi: orchestrator (root)
ve worker (non-root UID 10001) aynı paylaşılan `staging` Docker volume'una
yazıyor; orchestrator önce dizini oluşturduğunda worker'ın içine yazma
izni olmuyordu (`PermissionError: [Errno 13]`). `core/worker_protocol.py`
artık paylaşılan `input/`/`output/` dizinlerini `0o777` ile oluşturuyor
(gerekçe: bu tek-makine içinde paylaşılan bir staging alanı, gerçek
izolasyon sınırı `network_mode:none` + `cap_drop: ALL` + `read_only`
rootfs'tir — bkz. master_prompt.md 5). Düzeltme sonrası canlı testte sıfır
hata ile 81 iş tamamlandı.
