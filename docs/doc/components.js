const NAV = [
  { section: 'GETTING STARTED' },
  { slug: 'index',         label: 'Overview',       href: '../index/' },
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
          width: 220px;
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
          padding: 40px 48px;
        }

        .page {
          max-width: 860px;
          margin: 0 auto;
        }

        @media (max-width: 768px) {
          :host { flex-direction: column; }
          .sidebar { width: 100%; height: auto; position: static; }
          .content { padding: 24px 20px; }
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
        <div class="page">
          <slot></slot>
        </div>
      </div>
    `;
  }
}

customElements.define('primer-doc-layout', PrimerDocLayout);
