import page from '../../shared/mcp-consent.json';

const escape = (s: string) => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));

export async function renderConsentPage(input: {
  client: string; account: string; resource: string; callback: string; request: string;
  changeAccount: string; requested: string[]; dynamic: boolean; portal?: { name: string; loginUrl: string };
}) {
  const portalUrl = new URL(input.portal?.loginUrl || input.resource).origin;
  const portalHost = new URL(portalUrl).host;
  const brand = page.brands[portalHost as keyof typeof page.brands];
  const css = page.css.join('\n');
  const hash = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(css)))));
  const values: Record<string, string> = {
    client: escape(input.client), account: escape(input.account), shortName: escape(brand?.shortName || input.portal?.name || 'OrgPortal'),
    brandName: escape(brand?.name || input.portal?.name || 'OrgPortal'), tagline: escape(brand?.tagline || 'ACCOUNT AUTHORIZATION'),
    portalUrl: escape(portalUrl), portalHost: escape(portalHost), resource: escape(input.resource), callback: escape(input.callback),
    request: escape(input.request), changeAccount: escape(input.changeAccount), css,
    logo: brand ? `<img src="${escape(brand.logo)}" alt="${escape(brand.name)} logo" width="52" height="52">` : '',
    permissions: input.requested.map(scope => {
      const item = page.permissions[scope as keyof typeof page.permissions];
      return `<li><span class="check" aria-hidden="true">&#10003;</span><div><strong>${escape(item[0])}</strong><p>${escape(item[1])}</p></div></li>`;
    }).join(''),
    notice: input.dynamic ? '<p class="client-notice">This client name is self-reported, not verified by PIdP. Only continue if you started this connection.</p>' : '',
  };
  return { html: page.html.join('\n').replace(/\{\{(\w+)\}\}/g, (_, key) => values[key]),
    policy: `style-src 'sha256-${hash}'; img-src ${brand ? new URL(brand.logo).origin : "'none'"}` };
}
