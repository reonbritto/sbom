const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>SBOM Vulnerability Analyzer — API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui.css" />
  <script>
    (function(){try{var t=localStorage.getItem('theme');if(!t){t=window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';}document.documentElement.setAttribute('data-theme',t);}catch(e){}})();
  </script>
  <style>
    :root, html[data-theme='dark'] {
      --bg: #0b0d12;
      --panel: #11141b;
      --panel-2: #161a23;
      --border: #1f2430;
      --text: #e6e8ee;
      --text-dim: #9aa3b2;
      --accent: #6aa3ff;
      --accent-2: #4f7dd1;
      --critical: #ff4d6d;
      --high: #ff8c42;
      --low: #6dd3a8;
      --code-bg: #161a23;
    }
    html[data-theme='light'] {
      --bg: #f6f7fb;
      --panel: #ffffff;
      --panel-2: #f0f2f7;
      --border: #d8dde6;
      --text: #1a1d23;
      --text-dim: #5b6271;
      --accent: #2f6fed;
      --accent-2: #1e4cb0;
      --critical: #d23656;
      --high: #d97026;
      --low: #239363;
      --code-bg: #f0f2f7;
    }
    html { color-scheme: dark; }
    html[data-theme='light'] { color-scheme: light; }

    * { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      line-height: 1.5;
    }

    .header-bar {
      background: var(--panel); color: var(--text);
      padding: 12px 24px; border-bottom: 1px solid var(--border);
      display: flex; justify-content: space-between; align-items: center;
      font-family: inherit;
    }
    .header-bar .brand { font-weight: 600; font-size: 16px; }
    .header-bar nav { display: flex; gap: 16px; align-items: center; }
    .header-bar a {
      color: var(--text); text-decoration: none; font-size: 14px;
    }
    .header-bar a:hover { color: var(--accent); }
    .theme-toggle {
      background: transparent; border: 1px solid var(--border); color: var(--text);
      width: 36px; height: 36px; border-radius: 6px; cursor: pointer;
      display: inline-flex; align-items: center; justify-content: center;
      font-size: 16px;
    }
    .theme-toggle:hover { background: var(--panel-2); border-color: var(--accent); }

    /* Swagger UI overrides — adopt app typography + palette */
    .swagger-ui {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
      color: var(--text) !important;
    }
    .swagger-ui .topbar { display: none; }
    .swagger-ui .info { padding: 24px; }
    .swagger-ui .info .title,
    .swagger-ui .info p,
    .swagger-ui .info li,
    .swagger-ui .info a,
    .swagger-ui .scheme-container,
    .swagger-ui .opblock-tag,
    .swagger-ui .opblock .opblock-summary-method,
    .swagger-ui .opblock .opblock-summary-path,
    .swagger-ui .opblock .opblock-summary-path__deprecated,
    .swagger-ui .opblock .opblock-summary-description,
    .swagger-ui .opblock-description-wrapper,
    .swagger-ui .opblock-description-wrapper p,
    .swagger-ui .opblock .opblock-section-header h4,
    .swagger-ui .opblock .opblock-section-header label,
    .swagger-ui .response-col_status,
    .swagger-ui .response-col_description,
    .swagger-ui .response-col_description__inner div.markdown,
    .swagger-ui .response-col_description__inner div.markdown p,
    .swagger-ui table thead tr td,
    .swagger-ui table thead tr th,
    .swagger-ui table tbody tr td,
    .swagger-ui .parameter__name,
    .swagger-ui .parameter__type,
    .swagger-ui .parameter__deprecated,
    .swagger-ui .parameter__in,
    .swagger-ui label,
    .swagger-ui section.models h4,
    .swagger-ui section.models h5,
    .swagger-ui .model-title,
    .swagger-ui .model,
    .swagger-ui .model-toggle,
    .swagger-ui .tab li,
    .swagger-ui .markdown p,
    .swagger-ui .renderedMarkdown p {
      color: var(--text) !important;
      font-family: inherit !important;
    }
    .swagger-ui .info .title { font-size: 24px !important; font-weight: 600 !important; }
    .swagger-ui .opblock-tag { font-size: 18px !important; font-weight: 600 !important; }
    .swagger-ui .opblock .opblock-summary-path { font-size: 14px !important; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace !important; }
    .swagger-ui .opblock-tag, .swagger-ui .opblock-tag-section h3 { border-bottom-color: var(--border) !important; }

    .swagger-ui .scheme-container,
    .swagger-ui section.models,
    .swagger-ui .opblock { background: var(--panel) !important; border-color: var(--border) !important; box-shadow: none !important; }
    .swagger-ui section.models.is-open h4 { border-bottom-color: var(--border) !important; }
    .swagger-ui .opblock-section-header { background: var(--panel-2) !important; box-shadow: none !important; }
    .swagger-ui .info .title small.version-stamp { background: var(--accent) !important; }

    .swagger-ui select, .swagger-ui input[type=text], .swagger-ui input[type=password], .swagger-ui input[type=email], .swagger-ui textarea {
      background: var(--panel-2) !important; color: var(--text) !important;
      border: 1px solid var(--border) !important;
      font-family: inherit !important;
    }

    .swagger-ui pre, .swagger-ui code, .swagger-ui .microlight {
      background: var(--code-bg) !important; color: var(--text) !important;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace !important;
      font-size: 12px !important;
    }
    .swagger-ui .highlight-code > .microlight { background: var(--code-bg) !important; }

    .swagger-ui .opblock.opblock-get { border-color: var(--accent) !important; background: rgba(106, 163, 255, 0.05) !important; }
    .swagger-ui .opblock.opblock-get .opblock-summary-method { background: var(--accent) !important; }
    .swagger-ui .opblock.opblock-post { border-color: var(--low) !important; background: rgba(109, 211, 168, 0.05) !important; }
    .swagger-ui .opblock.opblock-post .opblock-summary-method { background: var(--low) !important; }
    .swagger-ui .opblock.opblock-delete { border-color: var(--critical) !important; background: rgba(255, 77, 109, 0.05) !important; }
    .swagger-ui .opblock.opblock-delete .opblock-summary-method { background: var(--critical) !important; }
    .swagger-ui .opblock.opblock-put { border-color: var(--high) !important; background: rgba(255, 140, 66, 0.05) !important; }
    .swagger-ui .opblock.opblock-put .opblock-summary-method { background: var(--high) !important; }

    .swagger-ui .btn {
      background: var(--panel-2) !important;
      color: var(--text) !important;
      border: 1px solid var(--border) !important;
      font-family: inherit !important;
    }
    .swagger-ui .btn:hover { border-color: var(--accent) !important; }
    .swagger-ui .btn.execute { background: var(--accent) !important; color: #fff !important; border-color: var(--accent) !important; }
    .swagger-ui .btn.execute:hover { background: var(--accent-2) !important; border-color: var(--accent-2) !important; }
    .swagger-ui .btn.authorize { color: var(--low) !important; border-color: var(--low) !important; }
    .swagger-ui .btn.cancel { color: var(--critical) !important; border-color: var(--critical) !important; }

    .swagger-ui svg { fill: var(--text) !important; }
    .swagger-ui .arrow { fill: var(--text-dim) !important; }
  </style>
</head>
<body>
  <div class="header-bar">
    <span class="brand">SBOM Vulnerability Analyzer · API Docs</span>
    <nav>
      <a href="/">Dashboard</a>
      <a href="/upload">Upload</a>
      <a href="/api/openapi.json" target="_blank" rel="noreferrer">openapi.json</a>
      <button class="theme-toggle" type="button" id="theme-toggle" title="Toggle theme">🌗</button>
    </nav>
  </div>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui-bundle.js" crossorigin></script>
  <script src="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui-standalone-preset.js" crossorigin></script>
  <script>
    window.addEventListener('load', function () {
      window.ui = SwaggerUIBundle({
        url: '/api/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset.slice(1)],
        layout: 'BaseLayout',
        withCredentials: true,
        requestInterceptor: function (req) { req.credentials = 'include'; return req; },
        persistAuthorization: true,
        tryItOutEnabled: true,
      });
      var btn = document.getElementById('theme-toggle');
      function syncIcon(){ btn.textContent = (document.documentElement.getAttribute('data-theme') === 'light') ? '🌙' : '☀️'; }
      syncIcon();
      btn.addEventListener('click', function(){
        var next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', next);
        try { localStorage.setItem('theme', next); } catch(e){}
        syncIcon();
      });
    });
  </script>
</body>
</html>`;

export async function GET() {
  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8' } });
}
