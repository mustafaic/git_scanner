/* Satir menusu ("..." tusu) konumlandirmasi.

   SORUN: `.table-wrap` yatay kaydirma icin `overflow-x: auto` tasir. CSS
   spesifikasyonuna gore bir eksende auto/scroll varsa diger eksen de
   "visible" KALAMAZ -- yani panel dikeyde de kirpilir. Bu yuzden tablo
   icindeki `position: absolute` bir menu paneli tablonun kenarinda kesilip
   gorunmez oluyordu (bildirilen hata).

   COZUM: panel `position: fixed` (CSS'te tanimli) ve koordinatlari burada,
   tetikleyicinin ekrandaki gercek konumundan hesaplanir. `fixed` eleman
   kapsayicinin overflow'undan etkilenmez; ekran kenarina tasarsa sola/
   yukari cevrilir. */
document.addEventListener('DOMContentLoaded', function () {
  var menus = Array.prototype.slice.call(document.querySelectorAll('details.row-menu'));
  if (!menus.length) return;

  var MARGIN = 8;

  function place(menu) {
    var summary = menu.querySelector('summary');
    var panel = menu.querySelector('.popover-panel');
    if (!summary || !panel) return;

    // Olcebilmek icin once gorunur olmali; panel zaten details[open] ile acik.
    panel.style.top = '0px';
    panel.style.left = '0px';
    var trigger = summary.getBoundingClientRect();
    var box = panel.getBoundingClientRect();

    // Varsayilan: tetikleyicinin ALTINA, SAG kenarlari hizali.
    var left = trigger.right - box.width;
    var top = trigger.bottom + 4;

    if (left < MARGIN) left = MARGIN;
    if (left + box.width > window.innerWidth - MARGIN) {
      left = Math.max(MARGIN, window.innerWidth - MARGIN - box.width);
    }
    // Alta sigmiyorsa tetikleyicinin USTUNE ac.
    if (top + box.height > window.innerHeight - MARGIN) {
      var above = trigger.top - 4 - box.height;
      top = above >= MARGIN ? above : Math.max(MARGIN, window.innerHeight - MARGIN - box.height);
    }

    panel.style.left = left + 'px';
    panel.style.top = top + 'px';
  }

  function closeAll(except) {
    menus.forEach(function (m) {
      if (m !== except && m.open) m.open = false;
    });
  }

  menus.forEach(function (menu) {
    menu.addEventListener('toggle', function () {
      if (menu.open) {
        closeAll(menu);
        place(menu);
      }
    });
  });

  // Dis tiklama / Esc / kaydirma / yeniden boyutlandirma -> menuyu kapat.
  document.addEventListener('click', function (event) {
    if (!event.target.closest('details.row-menu')) closeAll(null);
  });
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') closeAll(null);
  });
  window.addEventListener('resize', function () { closeAll(null); });
  // Kaydirmada panel tetikleyiciden kopacagi icin kapatmak en dogrusu.
  window.addEventListener('scroll', function () { closeAll(null); }, true);
});
