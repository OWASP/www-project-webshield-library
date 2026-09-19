import { defineConfig } from "vitepress";

const referenceSidebar = [
  { text: "A01 — Broken Access Control", link: "/reference/a01-access-control" },
  { text: "A02 — Cryptographic Failures", link: "/reference/a02-crypto-integrity" },
  { text: "A03 — Injection", link: "/reference/a03-injection-defense" },
  { text: "A04 — Insecure Design", link: "/reference/a04-insecure-design-guard" },
  { text: "A05 — Security Misconfiguration", link: "/reference/a05-security-misconfiguration" },
  { text: "A06 — Vulnerable Components", link: "/reference/a06-vulnerable-components" },
  { text: "A07 — Auth & Session Failures", link: "/reference/a07-auth-session" },
  { text: "A08 — Data Integrity Failures", link: "/reference/a08-data-integrity" },
  { text: "A09 — Logging & Monitoring Failures", link: "/reference/a09-logging-monitoring" },
  { text: "A10 — Server-Side Request Forgery", link: "/reference/a10-ssrf-defense" },
  { text: "Typed Errors", link: "/reference/errors" }
];

export default defineConfig({
  title: "OWL",
  description: "OWASP Web Shield Library — practical OWASP Top 10 security controls for JavaScript",
  cleanUrls: true,
  lastUpdated: true,

  head: [["link", { rel: "icon", href: "/favicon.svg" }]],

  themeConfig: {
    logo: "/favicon.svg",
    nav: [
      { text: "Guide", link: "/guide/getting-started" },
      { text: "Reference", link: "/reference/a01-access-control" },
      { text: "FAQ", link: "/faq" },
      { text: "Changelog", link: "/changelog" },
      {
        text: "npm",
        items: [
          { text: "@owasp-core/owl", link: "https://www.npmjs.com/package/@owasp-core/owl" },
          { text: "@owasp-core/owl-react", link: "https://www.npmjs.com/package/@owasp-core/owl-react" }
        ]
      }
    ],

    sidebar: {
      "/guide/": [
        {
          text: "Guide",
          items: [
            { text: "Getting Started", link: "/guide/getting-started" },
            { text: "Module Map", link: "/guide/module-map" },
            { text: "React Adapter Setup", link: "/guide/react-setup" }
          ]
        }
      ],
      "/reference/": [
        {
          text: "Core API by OWASP Category",
          items: referenceSidebar
        }
      ]
    },

    search: {
      provider: "local"
    },

    socialLinks: [
      { icon: "github", link: "https://github.com/OWASP/www-project-webshield-library" },
      { icon: "npm", link: "https://www.npmjs.com/package/@owasp-core/owl" }
    ],

    editLink: {
      pattern: "https://github.com/OWASP/www-project-webshield-library/edit/main/website/:path",
      text: "Edit this page on GitHub"
    },

    footer: {
      message: "Released under the Apache 2.0 License.",
      copyright: "Copyright © OWASP Web Shield Library Project"
    }
  }
});
