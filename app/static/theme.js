(function () {
  var saved = localStorage.getItem('theme');
  if (saved === 'light' || saved === 'dark') {
    document.documentElement.setAttribute('data-theme', saved);
  }
})();

document.addEventListener('DOMContentLoaded', function () {
  var buttons = document.querySelectorAll('.js-theme-toggle');
  if (!buttons.length) return;

  function current() {
    var attr = document.documentElement.getAttribute('data-theme');
    if (attr === 'light' || attr === 'dark') return attr;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function render() {
    var isDark = current() === 'dark';
    buttons.forEach(function (btn) {
      var icon = btn.querySelector('.icon');
      var label = btn.querySelector('.label');
      if (icon) icon.textContent = isDark ? '☀️' : '\u{1F319}';
      if (label) label.textContent = isDark ? 'Açık moda geç' : 'Koyu moda geç';
      if (!icon && !label) btn.textContent = isDark ? '☀️' : '\u{1F319}';
      btn.setAttribute('aria-label', isDark ? 'Açık moda geç' : 'Koyu moda geç');
    });
  }

  buttons.forEach(function (btn) {
    btn.addEventListener('click', function () {
      var next = current() === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
      render();
    });
  });

  render();
});
