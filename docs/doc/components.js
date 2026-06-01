const NAV = [
  { section: 'GETTING STARTED' },
  { slug: 'index',         label: 'Overview',       href: '../index/' },
  { slug: 'quickstart',    label: 'Quickstart',     href: '../quickstart/' },
  { slug: 'installation',  label: 'Installation',   href: '../installation/' },
  { slug: 'configuration', label: 'Configuration',  href: '../configuration/' },
  { divider: true },
  { section: 'REFERENCE' },
  { slug: 'cli-reference', label: 'CLI Reference',  href: '../cli-reference/' },
  { divider: true },
  { section: 'INTEGRATIONS' },
  { slug: 'integrations',  label: 'Integrations',   href: '../integrations/' },
  { slug: 'git-hooks',     label: 'Git Hooks',      href: '../git-hooks/' },
  { slug: 'ai',            label: 'AI Layer',       href: '../ai/' },
  { slug: 'mcp',           label: 'MCP Server',     href: '../mcp/' },
];

const ICON_COPY = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>`;
const ICON_CHECK = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#35E0A1" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>`;

function addCopyButtons(root) {
  root.querySelectorAll('pre:not([data-copy])').forEach(pre => {
    pre.setAttribute('data-copy', '');
    const btn = document.createElement('button');
    btn.className = 'pre-copy-btn';
    btn.setAttribute('aria-label', 'Copy code');
    btn.innerHTML = ICON_COPY;
    btn.addEventListener('click', () => {
      const text = (pre.querySelector('code') ?? pre).textContent;
      navigator.clipboard.writeText(text).then(() => {
        btn.innerHTML = ICON_CHECK;
        setTimeout(() => { btn.innerHTML = ICON_COPY; }, 2000);
      });
    });
    pre.appendChild(btn);
  });
}

class PrimerDocLayout extends HTMLElement {
  connectedCallback() {
    const active = this.getAttribute('active') || '';
    const shadow = this.attachShadow({ mode: 'open' });

    const navItems = NAV.map(item => {
      if (item.section) {
        return `<div class="nav-section">${item.section}</div>`;
      }
      if (item.divider) {
        return `<hr class="nav-divider">`;
      }
      const isActive = item.slug === active;
      return `<a href="${item.href}" class="nav-link${isActive ? ' active' : ''}">${item.label}</a>`;
    }).join('');

    // Compute prev / next from flat page list
    const PAGES = NAV.filter(item => item.slug);
    const idx   = PAGES.findIndex(p => p.slug === active);
    const prev  = idx > 0              ? PAGES[idx - 1] : null;
    const next  = idx < PAGES.length - 1 ? PAGES[idx + 1] : null;

    const pageNavHTML = (prev || next) ? `
      <nav class="page-nav">
        ${prev
          ? `<a href="${prev.href}" class="page-nav-link page-nav-prev">
               <span class="page-nav-label">← Previous</span>
               <span class="page-nav-title">${prev.label}</span>
             </a>`
          : `<span></span>`}
        ${next
          ? `<a href="${next.href}" class="page-nav-link page-nav-next">
               <span class="page-nav-label">Next →</span>
               <span class="page-nav-title">${next.label}</span>
             </a>`
          : `<span></span>`}
      </nav>` : '';

    shadow.innerHTML = `
      <style>
        *, *::before, *::after { box-sizing: border-box; }

        :host {
          display: flex;
          min-height: 100vh;
          background: #f5f6fa;
          font-family: system-ui, -apple-system, sans-serif;
          font-size: 14px;
          color: #111827;
        }

        .sidebar {
          width: 260px;
          flex-shrink: 0;
          background: var(--dark);
          color: #cbd5e1;
          display: flex;
          flex-direction: column;
          position: sticky;
          top: 0;
          align-self: flex-start;
          height: 100vh;
          overflow-y: auto;
        }

        .logo {
          padding: 20px 20px 16px;
          font-weight: 700;
          font-size: 16px;
          color: #fff;
          letter-spacing: .02em;
          text-decoration: none;
          display: block;
        }

        .logo span { color: var(--accent); }

        .nav-section {
          padding: 8px 12px 4px;
          font-size: .65rem;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: .08em;
          color: #64748b;
        }

        .nav-link {
          display: block;
          padding: 7px 20px;
          color: #94a3b8;
          text-decoration: none;
          font-size: .85rem;
          border-left: 3px solid transparent;
          transition: color .15s, border-color .15s, background .15s;
        }

        .nav-link:hover {
          color: #e2e8f0;
          background: rgba(255,255,255,.05);
        }

        .nav-link.active {
          color: #fff;
          border-left-color: var(--accent);
          background: rgba(53,224,161,.12);
        }

        .nav-divider {
          border: none;
          border-top: 1px solid #334155;
          margin: 12px 0;
        }

        .sidebar-footer {
          margin-top: auto;
          padding: 16px 20px;
          font-size: .72rem;
          color: #475569;
          border-top: 1px solid #334155;
        }

        .sidebar-footer a {
          color: var(--accent);
          text-decoration: none;
        }

        .sidebar-footer a:hover { text-decoration: underline; }

        .sep { color: #334155; margin: 0 4px; }

        .content {
          flex: 1;
          overflow: auto;
          padding: 48px 64px;
        }

        /* ── Prev / Next navigation ── */
        .page-nav {
          display: flex;
          justify-content: space-between;
          gap: 12px;
          margin-top: 56px;
          padding-top: 24px;
          border-top: 1px solid #e2e4ea;
        }

        .page-nav-link {
          display: flex;
          flex-direction: column;
          gap: 4px;
          padding: 14px 18px;
          border: 1px solid #e2e4ea;
          border-radius: 8px;
          text-decoration: none;
          min-width: 160px;
          max-width: 46%;
          transition: border-color .15s, box-shadow .15s;
        }

        .page-nav-link:hover {
          border-color: var(--accent, #35E0A1);
          box-shadow: 0 2px 8px rgba(53,224,161,.12);
        }

        .page-nav-next { align-items: flex-end; margin-left: auto; }
        .page-nav-prev { align-items: flex-start; }

        .page-nav-label {
          font-size: .68rem;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: .07em;
          color: #94a3b8;
        }

        .page-nav-title {
          font-size: .88rem;
          font-weight: 600;
          color: var(--ink, #0f172a);
        }

        @media (max-width: 768px) {
          :host { flex-direction: column; }
          .sidebar { width: 100%; height: auto; position: static; }
          .content { padding: 24px 20px; }
          .page-nav { flex-direction: column; }
          .page-nav-link { max-width: 100%; }
          .page-nav-next { align-items: flex-start; margin-left: 0; }
        }
      </style>

      <aside class="sidebar">
        <a class="logo" href="../index/"><span>primer</span> docs</a>
        <nav>${navItems}</nav>
        <div class="sidebar-footer">
          <a href="https://primer.barestripe.com">primer.barestripe.com</a>
          <span class="sep">·</span>
          <a href="https://github.com/barestripehq/primer">GitHub</a>
        </div>
      </aside>

      <div class="content">
        <slot></slot>
        ${pageNavHTML}
      </div>
    `;

    // Inject copy buttons into all <pre> elements in the slot content
    const slot = shadow.querySelector('slot');
    slot.addEventListener('slotchange', () => {
      slot.assignedElements({ flatten: true }).forEach(el => addCopyButtons(el));
    });
    // Also run once for content already in DOM when connectedCallback fires
    setTimeout(() => addCopyButtons(this), 0);
  }
}

customElements.define('primer-doc-layout', PrimerDocLayout);
