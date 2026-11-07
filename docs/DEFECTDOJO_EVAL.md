# DefectDojo Değerlendirme Kontrol Listesi (Aşama 0)

**Bu listeyi bir insan doldurur.** Amaç: "sıfırdan inşa et" ile "DefectDojo üzerine
ince bir entegrasyon/otomasyon katmanı koy" kararını (master_prompt.md §7, Aşama 0
DUR noktası) somut kanıtla vermek. Aşağıdaki her madde için **Karşılıyor /
Kısmi (ek iş gerekir) / Karşılamıyor / Test edilmedi** işaretle ve bir **Not**
yaz (gerekirse ekran görüntüsü/log referansı).

## 0. Kurulum

- [ ] DefectDojo'yu resmi `docker-compose` ile **izole bir test ortamında**
  (şirketin production ağından ayrı, mümkünse internet erişimi kısıtlı bir
  sandbox'ta) kur. Gerçek şirket verisi/repo adı KULLANMA — fixture/örnek veri
  kullan (bkz. master_prompt.md §8 fixture listesi).
- [ ] Sürüm/commit: ________________ Kurulum tarihi: ________________
- [ ] Kurulum sırasında gözlenen dış ağ bağlantıları (varsa): ________________
  (DefectDojo'nun kendisi update-check/telemetry yapıyor mu? Bu ürünün en üst
  öncelikli kuralı şirket verisinin dışarı çıkmaması — bu nedenle bu adım
  zorunlu, atlanamaz.)

## 1. Scanner import / adaptör uyumu

| # | Kriter | Durum | Not |
|---|---|---|---|
| 1.1 | OSV-Scanner JSON çıktısını native import eden bir parser var mı? | | |
| 1.2 | Gitleaks JSON/SARIF çıktısını native import eden bir parser var mı? | | |
| 1.3 | Parser'lar "golden-file" tarzı sabit örnek çıktıyla test edilebiliyor mu (yani içe aktarma deterministik ve doğrulanabilir mi)? | | |
| 1.4 | Scanner sürümü yükseltildiğinde import'un bozulup bozulmadığını anlamak için bir mekanizma var mı? | | |
| 1.5 | Desteklenmeyen/bilinmeyen alanlar sessizce mi düşüyor, yoksa görünür bir uyarı mı veriyor? | | |

## 2. Finding modeli, dedup, yaşam döngüsü

| # | Kriter | Durum | Not |
|---|---|---|---|
| 2.1 | CVE/GHSA/OSV alias'larını tek kayda bağlayan bir dedup/alias mekanizması var mı? | | |
| 2.2 | Finding doğal anahtarı repo+lockfile yolu+component+vulnerability ID düzeyinde mi, yoksa daha kaba mı (ör. sadece CVE)? | | |
| 2.3 | Durumlar master_prompt.md §4.3'teki kümeyi (`OPEN, IN_PROGRESS, RESOLVED, REOPENED, FALSE_POSITIVE, NOT_AFFECTED, ACCEPTED_RISK`) karşılıyor mu, yoksa eşlenmesi mi gerekiyor? | | |
| 2.4 | Durum değişiklikleri **append-only** bir olay geçmişinde (audit) tutuluyor mu (kim/ne zaman/neden/kanıt)? | | |
| 2.5 | Suppression/FP/NOT_AFFECTED/ACCEPTED_RISK için **zorunlu gerekçe metni** zorlanabiliyor mu (config/politika ile)? | | |
| 2.6 | **Kritik:** "tarama/parse başarısız oldu" durumunda bulguların **otomatik RESOLVED olmaması** garanti edilebiliyor mu (yani re-import/reimport API'si parse hatasını nasıl ele alıyor — boş sonuç = "artık bulunamadı" mı sayılıyor)? Bu, sanity-gate gereksinimimizin can alıcı noktası. | | |
| 2.7 | Kapanmış bulgu tekrar görünürse `REOPENED` benzeri bir durum ve geçmiş koruması var mı? | | |
| 2.8 | Toplu (bulk) durum değişikliği + her biri için ayrı audit kaydı destekleniyor mu? | | |

## 3. Patchability, önceliklendirme, görünüm politikası

| # | Kriter | Durum | Not |
|---|---|---|---|
| 3.1 | "Fix mevcut / değil / bilinmiyor" ayrımı (patchability) tutuluyor mu? | | |
| 3.2 | Önerilen yükseltme sürümü hesaplaması var mı, yoksa sadece "fix_version" metni mi tutuluyor (otomatik hesap yok)? | | |
| 3.3 | CVSS eşiği + KEV listesi birleşik görünüm politikası (CVSS≥7 VEYA KEV'de) config'den kurulabiliyor mu? | | |
| 3.4 | EPSS skoru alanı/entegrasyonu var mı (native veya custom field ile)? | | |
| 3.5 | Skor kaynağı çelişkisi (GHSA/NVD/vendor, CVSS v3.1/v4.0) gösteriliyor mu, yoksa tek bir skor mu saklanıyor? | | |
| 3.6 | "Neden Verified / neden Needs Review" gibi açıklanabilir bir kanıt alanı var mı, yoksa custom field eklemek mi gerekiyor? | | |

## 4. Secret bulguları (Gitleaks'e özgü kurallar)

| # | Kriter | Durum | Not |
|---|---|---|---|
| 4.1 | Secret tipi bulgular için SCA'dan **ayrı bir lifecycle** (ör. "rotate edildi" onayı) kurgulanabiliyor mu? | | |
| 4.2 | Ham secret değerinin DB/log/API/UI'da hiçbir yerde görünmediği doğrulanabiliyor mu (import sırasında redaction'ı bozmuyor mu)? | | |
| 4.3 | Secret bulguları için anlık/ayrı bildirim kanalı tanımlanabiliyor mu? | | |

## 5. Coverage / sağlık, sahip yönlendirme, SLA

| # | Kriter | Durum | Not |
|---|---|---|---|
| 5.1 | "Taranmayan/dışlanan repo", "PARTIAL tarama", "N gündür doğrulanmadı" gibi coverage/sağlık görünümü var mı, yoksa raporlama custom mu kurulmalı? | | |
| 5.2 | Repo→takım/sahip eşlemesi (CODEOWNERS veya CSV import) native destekleniyor mu (Product/Engagement/Team modeline nasıl oturuyor)? | | |
| 5.3 | "Sahipsiz bulgu" listesi doğal olarak çıkarılabiliyor mu? | | |
| 5.4 | SLA hedefleri severity/KEV bazında config'den tanımlanabiliyor mu, `due_date` ve gecikenler listesi var mı? | | |
| 5.5 | Günlük/haftalık metrik snapshot'ı (açık/kapalı trend, MTTR) native mi, yoksa raporlama eklentisi mi gerekiyor? | | |

## 6. Aksiyon odaklılık (A1/A2/A6 — ürünün temel tasarım ilkesi)

| # | Kriter | Durum | Not |
|---|---|---|---|
| 6.1 | "Bir pakete yükseltme yapınca N repoda M bulgu kapanır" tarzı **aksiyon grubu** (fix-once-close-many) var mı? | | |
| 6.2 | Blast radius ("bu CVE/paket@sürüm hangi repolarda, kimin sorumluluğunda") saniyeler içinde sorgulanabiliyor mu (UI+API)? | | |
| 6.3 | "Bugün ekranı" tarzı aksiyon odaklı, baseline-sonrası-yeni filtrelenmiş bir giriş görünümü var mı? | | |
| 6.4 | Baseline modu (ilk tarama bulguları ayrı etiketli, bildirim üretmez) native mi? | | |

## 7. Bildirim, auth, API, operasyon

| # | Kriter | Durum | Not |
|---|---|---|---|
| 7.1 | Bildirimler konsolide/idempotent/sessiz-saat destekli mi, yoksa bulgu başına mesaj mı atıyor (gürültü riski)? | | |
| 7.2 | Yerel hesap + TOTP (2FA) + rol bazlı (en az admin/viewer ayrımı) auth destekleniyor mu? Harici IdP şart mı? | | |
| 7.3 | Read-only, scope'lu, süreli API token üretimi var mı? | | |
| 7.4 | CSV/JSON export (denetim kanıtı için) var mı? | | |
| 7.5 | Audit log (giriş, durum değişikliği, ayar değişikliği, export) kapsamlı mı? | | |
| 7.6 | Worker/scanner çalıştırma mimarisi bizim izolasyon modelimize (network_mode none, just-in-time staging) uyuyor mu, yoksa DefectDojo kendi import akışını mı dayatıyor (ve bu akış şirket kodunu nasıl/nerede işliyor)? | | |
| 7.7 | Yedekleme/restore prosedürü net mi (şifreli yedek bizim sorumluluğumuzda mı)? | | |

## 8. Genel değerlendirme

- **Toplam "Karşılamıyor" sayısı:** ________
- **Toplam "Kısmi" sayısı (tahmini ek geliştirme efor):** ________
- **En kritik eksik (varsa):** ________________________________________
- **Lisans/maliyet notu:** ________________________________________
- **Topluluk/bakım aktifliği (son commit tarihi, açık issue sayısı):** ________________________________________

### Tavsiye

- [ ] **Build (sıfırdan inşa)** — DefectDojo temel gereksinimlerin çoğunu
  karşılamıyor veya izolasyon/sanity-gate/aksiyon-odaklılık gibi kritik
  tasarım ilkelerini zorlaştırıyor.
- [ ] **DefectDojo + ince katman** — DefectDojo'yu finding store/lifecycle
  motoru olarak kullan, bizim orchestrator/worker/egress-proxy katmanımızı
  önüne koy, eksik parçaları (aksiyon grupları, coverage, baseline, SLA)
  üstüne ekle.
- [ ] **Belirsiz / daha fazla deneme gerekli**

Gerekçe (2-3 cümle): ________________________________________________________
______________________________________________________________________________

> Karar burada verilmez. Bu tablo Aşama 0 raporunun bir parçası olarak
> kullanıcıya sunulur; "build mi, DefectDojo üstüne ince katman mı" kararını
> kullanıcı verir (master_prompt.md §7, Aşama 0 DUR noktası).
