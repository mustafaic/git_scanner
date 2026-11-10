document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('select.auto-submit').forEach(function (select) {
    select.addEventListener('change', function () { select.form.submit(); });
  });

  var toggle = document.getElementById('sidebar-toggle');
  var sidebar = document.getElementById('sidebar');
  var backdrop = document.getElementById('sidebar-backdrop');
  if (!toggle || !sidebar || !backdrop) return;

  function close() {
    sidebar.classList.remove('open');
    backdrop.classList.remove('open');
    toggle.setAttribute('aria-expanded', 'false');
  }

  function open() {
    sidebar.classList.add('open');
    backdrop.classList.add('open');
    toggle.setAttribute('aria-expanded', 'true');
  }

  toggle.addEventListener('click', function () {
    if (sidebar.classList.contains('open')) close(); else open();
  });
  backdrop.addEventListener('click', close);
  sidebar.querySelectorAll('nav a').forEach(function (a) {
    a.addEventListener('click', close);
  });
});
