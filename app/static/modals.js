/* Onay pencereleri (native <dialog>).

   Yikici/geri alinamaz islemler (repo'yu taramadan cikarma, token kaldirma,
   kullaniciyi devre disi birakma, parola sifirlama, API token iptali...)
   dogrudan calismaz; once ekranin ortasinda, arkasi bulaniklastirilmis bir
   onay penceresi acilir ve islem SADECE onaylanirsa gonderilir.

   Native <dialog>.showModal() secildi cunku: odagi kendi icinde hapseder,
   Esc ile kapanir, "top layer"da render edildigi icin hicbir kapsayicinin
   overflow'u tarafindan kirpilmaz ve ::backdrop ile bulaniklastirma CSS'te
   tanimlanabilir -- yani kendi odak tuzagimizi yazmamiza gerek kalmaz.

   PROGRESSIVE ENHANCEMENT: tetikleyici bir <button type="button">, onay
   formu ise dialog icindeki GERCEK bir <form method="post">. <dialog>
   desteklenmiyorsa (cok eski tarayici) panel acilmaz; islem sessizce
   CALISMAZ -- yani "onaysiz calisma" riski olusmaz, guvenli tarafa duser. */
document.addEventListener('DOMContentLoaded', function () {
  var openers = document.querySelectorAll('[data-modal-open]');
  if (!openers.length) return;

  function dialogFor(el, attr) {
    var id = el.getAttribute(attr);
    if (!id) return null;
    var node = document.getElementById(id);
    return node && node.tagName === 'DIALOG' ? node : null;
  }

  openers.forEach(function (btn) {
    btn.addEventListener('click', function () {
      var dialog = dialogFor(btn, 'data-modal-open');
      if (!dialog || typeof dialog.showModal !== 'function') return;

      // Menu icinden aciliyorsa menuyu kapat -- arkada acik kalmasi
      // kafa karistirici olurdu.
      var menu = btn.closest('details.row-menu');
      if (menu) menu.open = false;

      dialog.showModal();

      // Ilk anlamli alana odaklan: varsa metin girisi, yoksa onay butonu.
      var field = dialog.querySelector('input:not([type=hidden]), textarea, select');
      if (field) field.focus();
    });
  });

  document.querySelectorAll('[data-modal-close]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var dialog = btn.closest('dialog') || dialogFor(btn, 'data-modal-close');
      if (dialog && typeof dialog.close === 'function') dialog.close();
    });
  });

  // Arka plana (backdrop) tiklayinca kapat: <dialog> kendisi tum ekrani
  // kaplar, bu yuzden tiklamanin ic panelin DISINDA olup olmadigina bakilir.
  document.querySelectorAll('dialog.modal').forEach(function (dialog) {
    dialog.addEventListener('click', function (event) {
      if (event.target !== dialog) return;
      var box = dialog.getBoundingClientRect();
      var inside = event.clientX >= box.left && event.clientX <= box.right
        && event.clientY >= box.top && event.clientY <= box.bottom;
      if (!inside) dialog.close();
    });
  });
});
