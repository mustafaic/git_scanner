# EGRESS_REPORT.md

master_prompt.md 5 "Doğrulama zorunlu": gerçek sistemde gözlenen ağ çıkışı
(zaman damgalı, gerçek log satırları), allowlist ile karşılaştırılmış.
Sentetik/varsayımsal değil — bu oturumda canlı `docker compose` stack'ine
karşı üretildi (2026-11-09).

## Yöntem

Paket yakalama (tcpdump) yerine **uygulamanın kendi yapılandırılmış
JSON logları** kullanıldı: `core/logging_setup.py` tüm çıkışı
yapılandırılmış JSON'a çevirir ve `httpx` kütüphanesinin kendi logger'ı
HER giden HTTP isteğini `"HTTP Request: <METHOD> <TAM-URL> \"<status>\""`
formatında loglar (orchestrator'ın TEK HTTP istemcisi `httpx`'tir — hem
GitHub API hem mirror indirmeleri için). Bu, ağ seviyesinde paket
yakalamadan DAHA KESİN bir denetim sağlar: tam URL/endpoint görülür, sadece
IP/port değil.

İki ayrı pencere gözlendi:
1. **Doğal çalışma** (~00:22–00:27 UTC, ~5 dakika): orchestrator'ın kendi
   poll loop + claim loop döngüsü, hiçbir elle müdahale yok.
2. **Günlük işler (mirror sync)**, elle tetiklendi (`orchestrator/mirror.py`
   fonksiyonları doğrudan çağrılarak) — normalde 24 saatte bir otomatik
   çalışır, ~17 saat sonra tekrar çalışacaktı; aynı kod yolu, sadece
   zamanlamayı beklemek yerine şimdi çalıştırıldı.

## Gözlenen pencere 1: doğal çalışma (poll + claim loop)

```
00:22:49 POST https://api.github.com/graphql -> 200 OK
00:23:50 POST https://api.github.com/graphql -> 200 OK
00:24:52 POST https://api.github.com/graphql -> 200 OK
00:25:53 POST https://api.github.com/graphql -> 200 OK
00:26:54 POST https://api.github.com/graphql -> 200 OK
```

**Tek host: `api.github.com`.** ~60 saniyelik periyotla (yapılandırılan
`POLL_INTERVAL_SECONDS`), GraphQL batch HEAD-SHA sorgusu
(`orchestrator/triggers.py::poll_head_shas`). Bu oturumun başında ayrıca
installation access token yenileme çağrısı da gözlendi
(`POST /app/installations/<id>/access_tokens`, aynı host).

## Gözlenen pencere 2: günlük mirror sync (elle tetiklendi)

```
GET https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json -> 200 OK   (KEV, 1769 kayıt)
GET https://epss.empiricalsecurity.com/epss_scores-current.csv.gz -> 302 Found
GET https://epss.empiricalsecurity.com/epss_scores-2026-11-08.csv.gz -> 200 OK                               (EPSS, 401 956 kayıt)
GET https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip -> 200 OK                           (OSV crates.io DB, 3 799 857 bayt)
```

**3 host:** `raw.githubusercontent.com`, `epss.empiricalsecurity.com`,
`osv-vulnerabilities.storage.googleapis.com`. Diğer 7 OSV ekosistemi
(npm, PyPI, Go, Packagist, Maven, RubyGems, NuGet) AYNI host'u
(`osv-vulnerabilities.storage.googleapis.com`) farklı path'lerle kullanır
— bu oturumda hepsini tekrar indirmek yerine PERF.md bölüm 1'deki önceki
ölçüm (2026-11-08, aynı host, 8 ekosistem) referans alındı.

## Allowlist karşılaştırması

| Gözlenen host | Beklenen mi? | Not |
|---|---|---|
| `api.github.com` | ✅ Evet | GitHub App auth + GraphQL/REST (kod/repo verisinin zaten bulunduğu yer) |
| `raw.githubusercontent.com` | ✅ Evet (**düzeltme**) | KEV için fiili host BU'dur, `cisa.gov` değil (403 veriyor, VERIFIED_FACTS.md madde 4) — **RUNBOOK.md'deki allowlist listesi `github.com` yerine `raw.githubusercontent.com` olarak güncellenmeli** |
| `epss.empiricalsecurity.com` | ✅ Evet | EPSS toplu CSV |
| `osv-vulnerabilities.storage.googleapis.com` | ✅ Evet | OSV-Scanner offline DB (GCS bucket, VERIFIED_FACTS.md) |
| *(başka hiçbir host)* | — | Gözlenmedi |

**Sonuç: beklenmeyen HİÇBİR host'a bağlantı gözlenmedi.** Tüm trafik
dokümante edilen 4 kaynağa gitti (RUNBOOK.md §5'teki host listesi
`raw.githubusercontent.com` olarak düzeltilmesi gerektiği not edilerek).

## İstek içeriği denetimi

GraphQL sorgusunun gövdesi (`orchestrator/triggers.py::poll_head_shas`)
repo owner/name içerir — bu **GitHub'ın kendisine** gönderilir (kodun
zaten bulunduğu yer, madde 5(a) ile tutarlı), üçüncü bir tarafa DEĞİL.
Mirror indirmeleri (KEV/EPSS/OSV) **hiçbir istek parametresi/body
içermez** — düz `GET` ile toplu dosya indirme, hiçbir repo/paket adı
URL'de veya header'da YOK.

## Worker ağsızlığı — yeniden doğrulama

Bu oturumda `docker inspect deploy-worker-1` ile tekrar kontrol edildi:
```
NetworkMode: none
NetworkSettings.Networks: {"none": {... IPAddress: ""}}
```
Worker'a hiçbir ağ arayüzü/IP atanmamış durumda — yapısal olarak hiçbir
TCP bağlantısı KURULAMAZ (VERIFIED_FACTS.md madde 9'daki `OSError: Network
is unreachable` testiyle tutarlı, bu oturumda ayrıca yapılandırma
seviyesinde teyit edildi).

## Bilinen sınırlama

Bu rapor **orchestrator ve worker** servislerini kapsar. `app` (panel) ve
`watchdog` servisleri de HTTP istemcisi (`httpx`) kullanabilir
(watchdog → `HEARTBEAT_URL`, varsayılan boş/devre dışı) ama bu oturumda
ayrıca denetlenmedi -- `app` servisinin kod incelemesi (`app/` dizininde
`httpx` import'u YOK, sadece `core.db`/Postgres) hiçbir dış ağ çağrısı
yapmadığını zaten gösteriyor (bkz. `app/main.py` docstring: "app servisi
... orchestrator modullerini import ETMEZ").
