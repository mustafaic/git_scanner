# LIMITATIONS.md

Bilinen kör noktalar ve ölçülmemiş/yapılmamış doğrulamalar (master_prompt.md
7 — Aşama 5 deliverable). Buradaki hiçbir madde "bir gün düzeltilecek bug"
değil — kasıtlı kapsam sınırları veya henüz ampirik olarak doğrulanmamış
noktalardır. Her madde, ilgili kod/karar kaydına referans verir.

## Kapsam dışı bırakılan özellikler (kullanıcı/tasarım kararı)

1. **Webhook alıcısı (Aşama 2b) hiç açılmadı.** Sistem SADECE hızlı yoklama
   (60 sn varsayılan) + elle tetikleme + günlük uzlaştırma ile çalışır.
   Commit→bulgu gecikmesi yoklama aralığına bağlıdır (bkz. PERF.md bölüm 3:
   tipik 30-90 sn, en kötü durum ~150 sn). Kullanıcı kararı: VERIFIED_FACTS.md
   sonundaki "KULLANICI KARARLARI" notu.
2. **TOTP (2FA) tamamen kaldırıldı** (2026-11-09, ASSUMPTIONS.md #14).
   Kimlik doğrulama tek faktörlüdür (kullanıcı adı + parola). Argon2id
   hash'leme, giriş rate-limit + geçici kilitleme ve oturum güvenliği
   (HttpOnly+SameSite, boşta zaman aşımı) değişmedi.
3. **Teams webhook entegrasyonu yok.** Sadece iç SMTP bildirim kanalı var
   (`app/routes_settings.py`). Teams webhook URL'si DB'de şifreli saklama
   gerektirir (master_prompt.md 5) ve bu henüz uygulanmadı.
4. **CODEOWNERS otomatik tespiti yok.** Sahip eşlemesi (A5) sadece admin'in
   içe aktardığı CSV ile çalışır (ASSUMPTIONS.md #13). Şema (`repo_owners.source`)
   CODEOWNERS desteğine hazır, ama orchestrator'da henüz bir senkron adımı
   yok.
5. **Repo bazlı tarama dahil/hariç politikası var ama arşiv/fork için
   otomatik varsayılan YOK.** Admin her repoyu tek tek hariç tutmalı
   (`app/routes_repos.py`); "arşiv/fork'lar varsayılan olarak hariç" kuralı
   master_prompt.md 6 A3'te istenmişti ama uygulanmadı.
6. **Viewer'a repo bazlı erişim kapsamı yok** (master_prompt.md 6: "repo
   bazlı kapsam v1.1" — kasıtlı olarak v1 dışı). Her viewer TÜM repoların
   bulgularını görür; bu yüzden viewer hesapları "yalnızca gerektiği kadar"
   açılmalı (madde zaten master_prompt'ta uyarılmıştı).
7. **GitHub yazma izni (PR yorumu, check/status) yok.** App SADECE okuma
   izinleriyle kuruldu; commit anında GitHub'a geri bildirim madde 6
   İletişim modeli'nde açıkça "MVP'de yok, v1.1" olarak işaretlenmişti.

## Ölçülmemiş / doğrulanamayan noktalar

8. **Precision/recall raporu yok.** master_prompt.md 8'deki TP/FP/FN
   karşılaştırması (`tools/dependabot_compare.py`) **hiç yazılmadı** —
   bunun için gerçek bir GitHub org'unda Dependabot alert'leri olan repolar
   gerekir; bu depoda elle oluşturulmuş fixture'lar var (tests/fixtures/)
   ama sistematik bir TP/FP/FN sayımı/karşılaştırması yapılmadı. İnsan
   tarafından, gerçek bir org ile çalıştırılması gerekir (madde 8'in kendi
   tanımı).
9. **24 saatlik kesintisiz çalışma denemesi yapılmadı.** Servisler bu
   oturum boyunca (birkaç saat) kesintisiz ayakta kaldı (restart olmadan),
   ama resmi bir 24 saatlik soak test bu depoda çalıştırılmadı/kayıt altına
   alınmadı.
10. **GraphQL batch sorgusunun gerçek point maliyeti** sadece küçük bir org
    (23 repo) ile gözlendi, büyük ölçekte (yüzlerce/binlerce repo)
    ölçülmedi (ASSUMPTIONS.md #4).
11. **GHES (GitHub Enterprise Server) hiç test edilmedi.** Kod GHES API
    taban yollarını destekleyecek şekilde yazıldı (`GITHUB_API_BASE_URL`
    konfigüre edilebilir) ama gerçek bir GHES örneğine karşı hiç
    çalıştırılmadı (ASSUMPTIONS.md #7).
12. **pom.xml (Maven) `manifest_only` sayılıyor, Verified asla olamaz**
    (ASSUMPTIONS.md #5) — gerçek bir Maven projesiyle offline modda
    doğrulanmadı.
13. **Cargo (Rust) için `SemverVersion` fallback kullanılıyor**, Cargo'ya
    özel bir sürüm sınıfı yok (ASSUMPTIONS.md #10) — gerçek bir zafiyetli
    Rust crate fixture'ıyla doğrulanmadı.

## Bilinen tasarım sınırlamaları (davranış, bug değil)

14. **Sadece varsayılan dal (default branch) taranır.** Diğer dallardaki
    zafiyetler/secret'lar hiç görünmez (`app/templates/coverage.html`
    "Bilinen kör noktalar" bölümünde panelde de gösterilir).
15. **"Lockfile'sız repo" sinyali gürültülü.** `orchestrator/extraction.py`
    bir repoda hiç lockfile bulamadığında `details.files=[]` yazar; bu,
    "repo'da lockfile eksik" ile "repo'nun hiç bağımlılığı yok" durumlarını
    AYIRT ETMEZ (`app/routes_coverage.py` docstring'inde not edilmiştir).
16. **SCA bulgularında satır numarası yok** (A4 kanıt paneli kısmi):
    `Finding` modeli lockfile yolu/sürüm/PURL tutar ama dosya içindeki satır
    numarasını TUTMAZ (lockfile formatları genelde anlamlı bir "satır"
    kavramına sahip değil). Secret bulgularında satır numarası VAR
    (`SecretFinding.line_number`, gitleaks'ten gelir).
17. **Günlük özet sahip/ekip bazlı AYRIŞTIRILMIYOR.** A6 bildirim motoru
    (`core/notifications.py`) tek bir konsolide özeti TÜM aktif alıcılara
    gönderir; master_prompt.md 6 A6'nın istediği "repo→sahip→alıcı eşlemesi
    varsa sahip bazlı ayrı özet" henüz uygulanmadı (A5 CSV sahip eşlemesi
    var ama bildirim motoruna henüz bağlanmadı).
18. **Tek orchestrator instance'ı varsayılır** — iş kuyruğu (`SELECT ... FOR
    UPDATE SKIP LOCKED`) çoklu instance'ı DB seviyesinde destekler ama
    poll/daily-jobs loop'ları (tetikleyici üretme, mirror sync) birden
    fazla instance'da ÇİFTE ÇALIŞIR hale gelir — şu an tekilleştirme/lider
    seçimi yok.
19. **Şifreli yedek Fernet ile TEK parça halinde şifrelenir** (chunked/
    streaming değil) — bkz. `core/backup_crypto.py` docstring'i. Bu
    projenin ölçeğinde (bkz. PERF.md) sorun değil; çok büyük bir
    veritabanında bellek kullanımı artar.
20. **Yedekleme otomatik zamanlanmış değil** — `tools/backup.py` host
    cron/Task Scheduler ile manuel tetiklenmesi gerekir (bkz. RUNBOOK.md);
    compose içinde kendi kendini tekrarlayan bir backup loop'u YOK (kural
    11: basit başlanır).
21. **Egress doğrulama raporu** — bkz. `docs/EGRESS_REPORT.md` (ayrı
    belge, bu oturumda ayrıca üretildi/üretilecek).
