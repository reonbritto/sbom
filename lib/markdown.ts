function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderInline(text: string): string {
  let out = escapeHtml(text);
  out = out.replace(/`([^`]+)`/g, (_, code) => `<code>${code}</code>`);
  out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  out = out.replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>');
  out = out.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, (_, label, url) =>
    `<a href="${url}" target="_blank" rel="noreferrer">${label}</a>`,
  );
  out = out.replace(
    /(^|[^"=])(https?:\/\/[^\s<)]+)/g,
    (_, lead, url) => `${lead}<a href="${url}" target="_blank" rel="noreferrer">${url}</a>`,
  );
  return out;
}

export function renderMarkdown(md: string): string {
  if (!md) return '';
  const lines = md.replace(/\r\n/g, '\n').split('\n');
  const out: string[] = [];
  let i = 0;
  let inList = false;
  let inCode = false;
  let codeLang = '';
  let codeBuf: string[] = [];

  const closeList = () => { if (inList) { out.push('</ul>'); inList = false; } };
  const flushCode = () => {
    out.push(`<pre><code${codeLang ? ` class="lang-${codeLang}"` : ''}>${escapeHtml(codeBuf.join('\n'))}</code></pre>`);
    codeBuf = [];
    codeLang = '';
    inCode = false;
  };

  while (i < lines.length) {
    const raw = lines[i];
    const line = raw.trimEnd();

    if (inCode) {
      if (/^```/.test(line.trim())) flushCode();
      else codeBuf.push(raw);
      i++; continue;
    }
    const fence = line.match(/^```([a-zA-Z0-9_+-]*)\s*$/);
    if (fence) {
      closeList();
      inCode = true;
      codeLang = fence[1] ?? '';
      i++; continue;
    }

    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      closeList();
      const level = heading[1].length;
      out.push(`<h${level + 2}>${renderInline(heading[2])}</h${level + 2}>`);
      i++; continue;
    }

    const bullet = line.match(/^[-*]\s+(.+)$/);
    if (bullet) {
      if (!inList) { out.push('<ul>'); inList = true; }
      out.push(`<li>${renderInline(bullet[1])}</li>`);
      i++; continue;
    }

    if (line.trim() === '') {
      closeList();
      i++; continue;
    }

    closeList();
    const para: string[] = [line];
    i++;
    while (i < lines.length && lines[i].trim() !== '' && !/^(#{1,6}\s|[-*]\s|```)/.test(lines[i])) {
      para.push(lines[i]);
      i++;
    }
    out.push(`<p>${renderInline(para.join(' '))}</p>`);
  }

  if (inCode) flushCode();
  closeList();
  return out.join('\n');
}
