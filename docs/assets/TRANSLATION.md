# Documentation translation

Every HTML page under `docs/` loads `docs-translate.css` and the shared deferred
`docs-translate.js` controller using relative URLs. This also works when the site
is hosted below a path prefix. Raw Markdown and `llms.txt` remain original sources.

English is the default. The native language selector offers English, Spanish,
Simplified/Traditional Chinese, French, German, Portuguese, Japanese, Korean,
Russian, Arabic, and Hindi. A choice is stored as `nedb.docs.language` and carried
in `docs-language` links; URL selection wins. Denied browser storage does not
break navigation. Switching languages reloads the original document, avoiding
translation of already translated text. The English-original link always works.

The local vendor bundle is loaded only for a non-English selection. No translation
requests occur while viewing English. The pinned, unchanged MIT source and license
are in `vendor/translate.js/`; its README records the upstream commit and checksum.
There are no CDN script dependencies or automatic vendor updates.

Translation uses the public HTTPS `translate.service` backend at
`https://api.translate.zvo.cn/`. Vendoring the client does **not** make translation
offline: selected documentation text is sent to that backend. No credentials are
embedded. Change the explicit host in the controller for a self-hosted service.
Service availability and translation accuracy are external dependencies. Errors
and a 20-second timeout expose an accessible status and the English-original link;
original content is never hidden. Partial results may remain when a batch fails.

`pre`, `code`, `kbd`, `samp`, form controls, SVG/math, terminal/endpoint elements,
version labels, and elements marked `translate="no"` or `.notranslate` are excluded.
Product names in prose are wrapped as excluded spans before translation. Authors
should put API identifiers, SQL, paths, and shell commands in semantic code tags.
The static docs do not need a DOM mutation listener; one page load translates once.

Validation: install Playwright in your development environment, then run
`node tests/docs_translation.cjs`. The test starts a local server and exercises the
actual vendored client with deterministic translation API responses. It checks
all HTML pages, English/no-network behavior, code integrity, navigation, storage
denial, RTL, and failure paths. This verifies integration behavior, not translation
quality or the uptime of the public backend.
