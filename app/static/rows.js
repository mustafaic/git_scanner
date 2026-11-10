/* Tiklanabilir tablo satirlari.
   Liste sayfalarinda satirin TAMAMI detay sayfasina gider (kullanici karari
   2026-11-11) -- oncesinde sadece hucre icindeki alti-cizili renkli link
   tiklanabilirdi.

   PROGRESSIVE ENHANCEMENT: her satirin birincil hucresinde GERCEK bir <a>
   durmaya devam eder (bkz. .row-link-target). Bu script sadece "satirin
   bos alanina tiklamak da ayni yere gitsin" davranisini ekler -- JS
   kapaliysa link normal sekilde calismaya devam eder, klavyeyle gezinme ve
   "yeni sekmede ac" (orta tus / Ctrl+tik) her durumda korunur. */
document.addEventListener('DOMContentLoaded', function () {
  var rows = document.querySelectorAll('tr.row-link[data-href]');
  if (!rows.length) return;

  // Satir icindeki kendi islevi olan ogelere yapilan tiklamalar satir
  // navigasyonunu TETIKLEMEZ (ör. "Hariç tut" butonu, popover ozeti, form
  // alani, hucredeki baska bir link).
  function isInteractive(target) {
    return !!target.closest('a, button, input, select, textarea, label, summary, details, form');
  }

  rows.forEach(function (row) {
    var href = row.getAttribute('data-href');

    row.addEventListener('click', function (event) {
      if (isInteractive(event.target)) return;
      // Kullanici metin seciyorsa (ör. bir SHA'yi kopyalamak icin) sayfayi
      // degistirmek can sikici olurdu.
      var selection = window.getSelection();
      if (selection && String(selection).length > 0) return;
      if (event.metaKey || event.ctrlKey || event.shiftKey) {
        window.open(href, '_blank', 'noopener');
        return;
      }
      window.location.assign(href);
    });

    // Orta tus = yeni sekmede ac (gercek bir link gibi davran).
    row.addEventListener('auxclick', function (event) {
      if (event.button !== 1 || isInteractive(event.target)) return;
      event.preventDefault();
      window.open(href, '_blank', 'noopener');
    });
  });
});
