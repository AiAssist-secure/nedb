/* NEDB documentation localization. Vendored client; explicit opt-in backend. */
(() => {
  'use strict';
  const assets = new URL('.', document.currentScript.src);
  const storageKey = 'nedb.docs.language';
  const languages = [
    ['english', 'en', 'English'],
    ['spanish', 'es', 'Español'],
    ['chinese_simplified', 'zh-Hans', '简体中文'],
    ['chinese_traditional', 'zh-Hant', '繁體中文'],
    ['french', 'fr', 'Français'],
    ['german', 'de', 'Deutsch'],
    ['portuguese', 'pt', 'Português'],
    ['japanese', 'ja', '日本語'],
    ['korean', 'ko', '한국어'],
    ['russian', 'ru', 'Русский'],
    ['arabic', 'ar', 'العربية'],
    ['hindi', 'hi', 'हिन्दी'],
  ];
  const url = new URL(location.href);
  let saved;
  try { saved = localStorage.getItem(storageKey); } catch (_) { /* English fallback. */ }
  const requested = url.searchParams.get('docs-language') ?? saved;
  const language = languages.find(item => item[0] === requested) || languages[0];
  const englishURL = new URL(url);
  englishURL.searchParams.set('docs-language', 'english');
  const panel = document.createElement('div');
  panel.className = 'docs-language notranslate';
  panel.translate = false;
  panel.lang = 'en';
  const label = document.createElement('label');
  label.htmlFor = 'docs-language';
  label.textContent = 'Language';
  const select = document.createElement('select');
  select.id = 'docs-language';
  for (const [value, lang, name] of languages) {
    const option = new Option(name, value);
    option.lang = lang;
    select.append(option);
  }
  select.value = language[0];
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  status.textContent = 'English original · translations by translate.js';
  const original = document.createElement('a');
  original.href = englishURL.href;
  original.textContent = 'View English original';
  const source = document.createElement('p');
  source.append(original);
  panel.append(label, select, status, source);
  const sidebar = document.querySelector('.sidebar');
  if (sidebar) {
    const brand = sidebar.querySelector('.brand, .sb-logo');
    if (brand) brand.after(panel); else sidebar.prepend(panel);
  } else {
    panel.classList.add('docs-language--standalone');
    const header = document.querySelector('header');
    if (header) header.after(panel); else document.body.prepend(panel);
  }
  select.addEventListener('change', () => {
    const next = new URL(location.href);
    next.searchParams.set('docs-language', select.value);
    // A fresh English DOM avoids accumulated translations and in-flight races.
    location.assign(next.href);
  });
  try { localStorage.setItem(storageKey, language[0]); } catch (_) { /* URL still works. */ }
  // Carry the choice between docs even when browser storage is disabled.
  const docsRoot = new URL('../', assets);
  document.querySelectorAll('a[href]').forEach(link => {
    const target = new URL(link.href);
    if (target.origin === docsRoot.origin && target.pathname.startsWith(docsRoot.pathname)
        && (target.pathname.endsWith('.html') || target.pathname.endsWith('/'))) {
      target.searchParams.set('docs-language', language[0]);
      if (link !== original) link.href = target.href;
    }
  });
  // English makes no translation requests and does not load the vendor script.
  if (language[0] === 'english') return;

  const excluded = 'pre,code,kbd,samp,script,style,svg,math,textarea,input,select,' +
    '.notranslate,[translate="no"],.brand,.sb-logo,#docsver,.mono,.terminal,.chain,.endpoint,.method';
  document.querySelectorAll(excluded).forEach(node => {
    node.classList.add('notranslate');
    node.setAttribute('translate', 'no');
  });
  // Protect product names in prose, not just inside code examples.
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walker.nextNode()) {
    if (!walker.currentNode.parentElement.closest(excluded)) nodes.push(walker.currentNode);
  }
  const terms = /\b(?:nedb-engine-client|nedb-engine|neSQL|nesql|NEDB|nedbd|NQL|PostgreSQL|SQL|PyPI|MongoDB|Redis|SQLite)\b/g;
  for (const node of nodes) {
    const text = node.textContent;
    const matches = [...text.matchAll(terms)];
    if (!matches.length) continue;
    const fragment = document.createDocumentFragment();
    let offset = 0;
    for (const match of matches) {
      fragment.append(text.slice(offset, match.index));
      const term = document.createElement('span');
      term.className = 'notranslate';
      term.translate = false;
      term.textContent = match[0];
      fragment.append(term);
      offset = match.index + match[0].length;
    }
    fragment.append(text.slice(offset));
    node.replaceWith(fragment);
  }
  let failed = false;
  const fail = () => {
    failed = true;
    panel.dataset.state = 'error';
    status.textContent = 'Translation unavailable or incomplete. The English original is always available.';
  };
  panel.dataset.state = 'loading';
  status.textContent = 'Translating with translate.js…';
  const deadline = setTimeout(fail, 20000);
  const script = document.createElement('script');
  script.src = new URL('vendor/translate.js/translate.js', assets).href;
  script.onerror = () => { clearTimeout(deadline); fail(); };
  script.onload = () => {
    try {
      const t = window.translate;
      t.selectLanguageTag.show = false;
      t.language.setLocal('english');
      t.autoDiscriminateLocalLanguage = false;
      t.to = language[0];
      t.ignore.class.push('notranslate', null);
      t.ignore.tag.push('kbd', 'samp', 'svg', 'math', 'textarea', 'input', 'select');
      t.service.use('translate.service');
      // One explicit public translation backend. No keys or engine data.
      t.request.setHost(['https://api.translate.zvo.cn/']);
      t.request.api.init = ''; // No update checks; this client is pinned locally.
      t.setDocuments([document.body]);
      t.lifecycle.execute.translateNetworkAfter.push(data => {
        if (data.result !== 1) fail();
      });
      t.lifecycle.execute.renderFinish.push(() => {
        clearTimeout(deadline);
        if (failed) return;
        panel.dataset.state = 'translated';
        document.documentElement.lang = language[1];
        document.documentElement.dir = language[0] === 'arabic' ? 'rtl' : 'ltr';
        status.textContent = 'Machine translation · translate.js';
      });
      t.execute();
    } catch (_) { clearTimeout(deadline); fail(); }
  };
  document.head.append(script);
})();
