/* Grafiklerin TEK SEFERLIK "çizilme" animasyonu (sayfa yüklenince).
   Sunucu her grafigi NIHAI dogru degeriyle render eder (bkz. app/chart_helpers.py,
   app/routes_analytics.py) -- bu script SADECE ilk boyama anini gizli bir
   baslangic durumundan nihai degere animasyonla tasir. JS kapaliysa veya
   prefers-reduced-motion: reduce ise hicbir sey yapilmaz, grafik zaten
   dogru/nihai halde gorunur (progressive enhancement, kural: temel
   islevsellik JS'e bagli degil). */
(function () {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  document.addEventListener('DOMContentLoaded', function () {
    animateDonuts();
    animateBars();
    animateTrendLines();
  });

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
