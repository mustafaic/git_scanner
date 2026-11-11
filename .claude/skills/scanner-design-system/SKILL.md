---
name: scanner-design-system
description: Scanner Panel'in görsel tasarım dili — renk/typography/spacing tokenları, bileşen sözlüğü ve kaçınılması gereken pratikler. Yeni sayfa veya component eklenirken, ya da mevcut template'lerde görsel değişiklik yapılırken bu dosyayı uygula.
---

# Scanner Panel Design System

Bu proje FastAPI + Jinja2 ile server-rendered bir güvenlik tarama paneli (SCA/secret bulgular, repo coverage, kullanıcı/owner yönetimi). Tek bir sayfa düzinelerce defa çoğaltılmış gibi görünmemeli — hepsi aynı token setini ve component sözlüğünü paylaşmalı.

## Token kaynağı

Tüm renk/typography/spacing/radius/shadow değişkenleri **`app/static/css/tokens.css`** içinde `:root` olarak tanımlı (light tema varsayılan, `@media (prefers-color-scheme: dark)` ve `:root[data-theme="dark"]`/`:root[data-theme="light"]` override'ları ile dark tema ve manuel toggle destekleniyor — toggle `app/static/theme.js`'de, `.js-theme-toggle` class'ına sahip TÜM butonları yönetir). Yeni bir renk/boşluk değeri gerekiyorsa **önce buraya bir token olarak ekle**, template içine hardcoded hex/px yazma.

**Severity renkleri EVRENSEL ve TEMADAN BAĞIMSIZ (2026-11-11, kullanıcı kararı):** Low `#39B54A` yeşil · Medium `#FCEE21` sarı · High `#F7931E` turuncu · Critical `#C1272D` kırmızı. Bu dört renk `tokens.css` içinde **yalnızca `:root` bloğunda** tanımlıdır ve tema bloklarında (ne dark ne light) yeniden tanımlanmaz — yani bir temada farklı görünmeleri yapısal olarak imkânsızdır. **Bu değerleri değiştirme ve severity için başka renk yazma.** Her seviyenin iki tokeni var: `--sev-X` (rengin kendisi: rozet arka planı, çubuk/donut dolgusu) ve `--sev-X-ink` (üzerine yazılacak metin rengi — hangisinin beyaz hangisinin koyu olduğu ölçülerek seçildi, hepsi ≥4.5:1). `--sev-none` ("skor yok") bir seviye değil veri yokluğudur: doygunluğu düşük nötr gri, tema ile değişir. **Trend/seri renkleri severity rampasından ALINMAZ** — `--chart-sca` (mavi) ve `--chart-secret` (mor) kullanılır, çünkü bir seri "şiddet" ifade etmez.

**Açık mod (2026-11-11):** yüzeyler bir kademe koyulaştırıldı ("çok parlak, göz alıyor" geri bildirimi) — `--surface` artık beyaz değil `#f1f3f6`, zemin `#e6e9ed`. Metin kontrastı hâlâ ~13:1; yeni bir açık-mod rengi eklerken bu parlaklık seviyesini koru, saf beyaza dönme.

**Dikey ritim (2026-11-11):** Sayfa gövdesindeki bloklar arası boşluk tek bir yerden gelir: `components.css` içindeki `main > * + * { margin-top: var(--gap-section) }`. Bileşenlere tek tek `margin-bottom` **yazma** — grid'ler de aynı tokeni `gap` olarak kullanır (`.stat-grid`, `.donut-row`, `.analytics-grid`). Tek istisna: bir başlık + hemen ardından gelen kendi `p.hint` alt açıklaması (bilinçli olarak daha yakın).

**Konsept (2026-11-10 redesign):** "Enstrüman paneli" -- renk sistemde TEK anlamlı yer tutucu: severity (critical/high/medium/low) ve durum rozetleri (success/warning/neutral/danger). Marka vurgusu sakin bir amber (`--brand`, light'ta `#966008`, dark'ta `#e3a53d` -- ikisi de AA kontrast (metin/arkaplan ≥4.5:1) için ölçülüp seçildi) -- parlak/neon değil, dekorasyon için her yere sürülmez (sadece aktif nav, primary buton, focus ring, brand noktası, grafik vurgusu). **Sidebar HER iki temada GERÇEKTEN farklı tonda** -- `--sidebar-bg` light modda açık gri-mavi (`#dde3e8`), dark modda koyu (`#0d1217`); "açık mod açıkken sidebar koyu kalıyor" artık mümkün değil, her iki `:root[data-theme=...]` bloğu kendi sidebar tonunu taşır. Sayısal degerler (stat kutuları, donut merkezi, tablo rozetleri) `ui-monospace`/tabular-nums ile -- "okunabilir enstrüman" hissi, yeni bir font yüklemeden (CSP `font-src 'self'`, yeni webfont bağımlılığı eklenmedi).

## Component sözlüğü (`app/static/css/components.css`)

- `.card` — içerik kutusu (padding, shadow, radius). Sayfa gövdesindeki her bağımsız blok bir `.card`.
- `.page-header` — sayfa başlığı + sağa hizalı aksiyonlar (export linkleri, butonlar). Her sayfanın `<h2>`'si bunun içinde olmalı, lone `<p>` içine link gömme.
- `.stat-grid` / `.stat` (+ `.stat-primary`, `.stat-alert`, `.stat-zero`) — dashboard KPI kutuları. `.stat-alert` sadece gerçek bir problem sinyaliyse (SLA geçti, KEV>0, açık secret); `.stat-zero` değer 0 ve bu iyi haberse.
- `.badge` + `.badge-<LIFECYCLE_STATUS>` ve `.sev-critical/high/medium/low` — durum/şiddet rozetleri.
- `.sev-bar` / `.sev-legend` — şiddet dağılım çubuğu.
- `.btn`, `.btn-primary`, `.btn-danger` — tüm butonlar/submit'ler bunlardan biri, ad-hoc inline-stillenmiş buton yok.
- `.flash-error` / `.flash-ok` — form sonucu/uyarı banner'ı.
- `.filter-bar` — liste sayfalarındaki filtre formu (select/input + auto-submit). Inline `style="margin-bottom:...; max-width:..."` yazma, bu class'ı kullan.
- `.table-wrap` — geniş `<table>`'ları saran, `overflow-x:auto` sağlayan konteyner (mobilde taşmayı önler). 4+ kolonlu her tablo bunun içinde olmalı.
- `.popover` (native `<details>/<summary>` üzerine) — satır içi onay/küçük form gerektiren aksiyonlar (örn. "repo hariç tut", "parola sıfırla") için. Yeni bir JS modal yazmak yerine bunu kullan — davranış native, sadece görünüm. Panel tetikleyicinin SAĞINA hizalanır (`right:0`) ve tablonun SON satırında yukarı açılır (`tbody tr:last-child`) -- bir `.table-wrap` içinde panel asla kırpılmamalı.
- `.row-actions` — bir tablo hücresinde birden fazla buton/popover varsa (örn. "Şimdi kontrol et" + "Hariç tut" + "Token'ı kaldır") HER ZAMAN bunun içine sarılmalı (`gap` ile ayrık, flex-wrap). Ard arda inline elemanları boşluksuz bırakmak "dip dibe" görünüme yol açar -- bunu kullan.
- `.muted` — ikincil/yardımcı metin (`style="color:#666"` yazma, bu class'ı kullan).
- `.text-danger` — hata/uyarı vurgulu metin (`style="color:#9b1c1c"` gibi hardcoded kırmızı yazma).
- `.donut-row`/`.donut-card`/`.donut-figure`/`.donut-center`/`.donut-legend` — analiz sayfasındaki büyük (satırı dolduran) donut grafikler, merkezde toplam sayı. `.hbar-list`/`.hbar-row`/`.hbar-track`/`.hbar-fill` — yatay bar grafikleri. `.trend-chart`/`.trend-line` — çizgi grafik. Bu üçü de `app/static/charts.js` tarafından sayfa yüklenince BİR KERE "çizilerek" animasyonla açılır (`prefers-reduced-motion: reduce` ise JS devre dışı, sunucunun render ettiği nihai değer direkt görünür).
- `.col-num` — liste tablolarının ilk sütunu: 1'den başlayan sıra numarası (`{{ loop.index }}`). Her liste tablosunda olmalı; sayfalanan listelerde numara sayfalar arasında SÜRER (bkz. `audit_log.html`, `page_size` ile). `colspan` değerlerini bu sütunu sayarak güncelle.
- `tr.row-link[data-href]` + `a.row-link-target` — tıklanabilir liste satırı. Satırın tamamı detaya gider (`app/static/rows.js`), ama birincil hücredeki **gerçek `<a>` korunur** (klavye, orta tuş, ekran okuyucu); o anchor `.row-link-target` ile renk/altı-çizili stilini kaybeder, etkileşim ipucu hover'da verilir. Satır içi butonlara/formlara yapılan tıklamalar navigasyonu tetiklemez.
- `.ts` + `| ts` Jinja filtresi (`app/deps.py::timestamp`) — **tüm** tarih/saat çıktıları bu filtreden geçer: `2026-11-11 18:08:58` (mikrosaniye/saat dilimi gösterilmez, tam ISO değer `title`'da korunur). Template'te ham `{{ x.created_at }}` yazma.
- **Onay penceresi — `confirm_action` makrosu (`_macros.html`).** Yıkıcı/geri alınamaz HER işlem (token iptali, parola sıfırlama, kullanıcıyı devre dışı bırakma, repoyu taramadan çıkarma, kayıtlı token kaldırma, istek silme) bu makroyla yapılır: `{% from "_macros.html" import confirm_action %}`. Makro tetikleyici butonu + ekranın ortasında açılan, arkası bulanıklaştırılmış native `<dialog>` onay penceresini birlikte üretir. Ek form alanı gerekiyorsa `{% call confirm_action(...) %}...{% endcall %}` ile gövdeye yazılır. **Yeni bir yıkıcı aksiyon eklerken kendi modalını yazma, bu makroyu kullan** — metin düzeni, buton sırası ve davranış her sayfada aynı kalsın. Onay butonunun etiketi ne olacağını söylemeli ("Token'ı iptal et"), "Tamam" değil.
- `.cell-actions` + `.row-actions` + `details.row-menu` — tablo satırı aksiyonları. Birincil aksiyon düz buton; ikincil/yıkıcı aksiyonlar tek bir `&ctdot;` menüsünde ve menü SADECE seçenek adlarını (`.menu-option`) taşır — formlar menüde değil onay penceresinde durur. Menü paneli `app/static/menus.js` ile `position: fixed` olarak konumlanır; bunu `absolute`'a çevirme — `.table-wrap`'in `overflow-x: auto`'su paneli kırpar (bu, daha önce bildirilmiş bir hatanın kök nedeniydi).
- `.cell-stack` — bir hücrede birbirine ait iki bilgi (ör. tarama politikası rozeti + canlı tarama durumu) dikey yığın halinde.
- Her liste tablosunda `{% for %}...{% else %}<tr><td colspan="N">Boş durum metni</td></tr>{% endfor %}` deseni zorunlu — boş state'i sessizce atlama.

## Yasaklı pratikler

- Her yere gradient eklemek (tek istisna: login sayfasının arka planındaki tek, çok hafif radial gradient -- `body:not(.with-sidebar)`).
- Her elementi farklı renkle vurgulamak — renk anlam taşımalı (severity/durum), dekorasyon değil.
- Inline `style="..."` ile rastgele spacing/renk — yukarıdaki class'lardan biri zaten var, onu kullan ya da tokens.css'e ekle.
- Sayfadan sayfaya farklı font/boşluk ritmi.
- "A · B · C" gibi orta-nokta ile birleştirilmiş meta string'ler, ALL-CAPS etiketler, başlığın üstüne gereksiz eyebrow label -- bunlar şablonsu/AI-tell okunur, kullanma.
- Her karta/bölüme jenerik giriş animasyonu (fade-in-up) uygulamak -- SADECE dashboard/analitik `.stat-grid.animate-in` (ilk görüş istatistik kutuları) ve grafikler (`charts.js`) bu hareketi kullanır. Yeni bir sayfaya "görünüş animasyonu" eklemeden önce bunun gerçekten tek, anlamlı bir an mı yoksa dekorasyon mu olduğunu sorgula.

## Responsive

Sidebar masaüstünde sabit 230px; `max-width: 860px` altında top bar + hamburger toggle'a dönüşür (bkz. `base.html`). Yeni sayfa eklerken bu breakpoint'i test et; geniş tabloları her zaman `.table-wrap` içine al.

## Dil

Arayüz dili Türkçe. Yeni metin eklerken mevcut sayfalardaki terminolojiyle tutarlı kal (örn. "Açık/Aktif", "İnceleme gerektiren", "Henüz ... yok.").
