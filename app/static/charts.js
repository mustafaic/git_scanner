/* Grafik davranislari: (1) tek seferlik "cizilme" animasyonu, (2) donut
   dilimi vurgulama/bilgi gosterimi.

   Sunucu her grafigi NIHAI dogru degeriyle render eder (bkz.
   app/chart_helpers.py, app/routes_analytics.py) -- bu script sadece ilk
   boyama anini animasyonla tasir ve etkilesim ekler. JS kapaliysa grafik
   zaten dogru/nihai halde gorunur (progressive enhancement).

   prefers-reduced-motion: reduce -> SADECE animasyonlar atlanir; dilim
   vurgulama/bilgi gosterimi calismaya devam eder, cunku o bir dekorasyon
   degil VERI tasir (hangi kategori, yuzde kac). */
(function () {
  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  document.addEventListener('DOMContentLoaded', function () {
    if (!reduceMotion) {
      animateDonuts();
      animateBars();
      animateTrendLines();
    }
    setupDonutHover();
  });

  /* Donut etkilesimi: uzerine gelinen dilim one cikar (kalinlasir, digerleri
     soluklasir) ve halkanin MERKEZI o dilimin adi + yuzdesine doner.
     Merkez kullanilmasinin nedeni: imlece gore kayan bir balon grafigin
     kenarinda kirpilabilir; merkez her zaman okunabilir ve zaten bakilan
     yerdir. Lejant satirlari da ayni vurguyu tetikler -- cok ince dilimleri
     fareyle yakalamak zor olabilir. */

  function setupDonutHover() {
    document.querySelectorAll('.donut-card').forEach(function (card) {
      var figure = card.querySelector('.donut-figure');
      var center = card.querySelector('.donut-center');
      if (!figure || !center) return;

      var segments = Array.prototype.slice.call(figure.querySelectorAll('.donut-seg'));
      var legendRows = Array.prototype.slice.call(card.querySelectorAll('.donut-legend .row'));
      if (!segments.length) return;

      var valueNode = center.querySelector('.n');
      var labelNode = center.querySelector('.l');
      if (!valueNode || !labelNode) return;

      var defaultValue = valueNode.textContent;
      var defaultLabel = labelNode.textContent;

      function activate(index) {
        var seg = segments[index];
        if (!seg) return;
        figure.classList.add('has-hover');
        segments.forEach(function (s, i) { s.classList.toggle('is-active', i === index); });
        legendRows.forEach(function (r, i) { r.classList.toggle('is-active', i === index); });
        valueNode.textContent = '%' + seg.getAttribute('data-pct');
        valueNode.classList.add('is-hint');
        labelNode.textContent = seg.getAttribute('data-label') + ' · ' + seg.getAttribute('data-value');
      }

      function reset() {
        figure.classList.remove('has-hover');
        segments.forEach(function (s) { s.classList.remove('is-active'); });
        legendRows.forEach(function (r) { r.classList.remove('is-active'); });
        valueNode.textContent = defaultValue;
        valueNode.classList.remove('is-hint');
        labelNode.textContent = defaultLabel;
      }

      segments.forEach(function (seg, index) {
        seg.addEventListener('mouseenter', function () { activate(index); });
        seg.addEventListener('mouseleave', reset);
      });
      legendRows.forEach(function (row, index) {
        row.addEventListener('mouseenter', function () { activate(index); });
        row.addEventListener('mouseleave', reset);
      });
    });
  }

  function reflow(el) { return el.getBoundingClientRect().height; }

  function animateDonuts() {
    document.querySelectorAll('circle.donut-seg').forEach(function (circle) {
      var finalDashArray = circle.getAttribute('stroke-dasharray');
      var finalOffset = circle.getAttribute('stroke-dashoffset');
      var r = parseFloat(circle.getAttribute('r')) || 40;
      var circumference = 2 * Math.PI * r;
      if (!finalDashArray) return;
      circle.setAttribute('stroke-dasharray', '0 ' + circumference.toFixed(3));
      circle.setAttribute('stroke-dashoffset', '0');
      reflow(circle);
      requestAnimationFrame(function () {
        circle.setAttribute('stroke-dasharray', finalDashArray);
        circle.setAttribute('stroke-dashoffset', finalOffset || '0');
      });
    });
  }

  function animateBars() {
    var selector = '.hbar-fill, .sev-bar span';
    document.querySelectorAll(selector).forEach(function (bar) {
      var finalWidth = bar.style.width;
      if (!finalWidth) return;
      bar.style.width = '0%';
      reflow(bar);
      requestAnimationFrame(function () {
        bar.style.width = finalWidth;
      });
    });
  }

  function animateTrendLines() {
    document.querySelectorAll('polyline.trend-line').forEach(function (line) {
      var points = line.getAttribute('points');
      if (!points || !points.trim()) return;
      var length = line.getTotalLength ? line.getTotalLength() : 0;
      if (!length) return;
      line.style.strokeDasharray = length + ' ' + length;
      line.style.strokeDashoffset = String(length);
      reflow(line);
      requestAnimationFrame(function () {
        line.style.transition = 'stroke-dashoffset var(--duration-chart, 900ms) var(--ease, ease)';
        line.style.strokeDashoffset = '0';
      });
    });
  }
})();
