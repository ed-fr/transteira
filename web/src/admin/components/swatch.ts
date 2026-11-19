// Colour of the decorative swatch of a tenant (TenantSwatch, home and entity lists; CLAUDE.md
// section 13.2). Tenant.primaryColor comes from the API, where it is validated already; it is
// validated again here (threat model T-417, defence in depth) and only ever rendered as the fill
// attribute of an SVG rect, never in a style attribute (strict CSP). Anything but #RRGGBB gives
// null: the swatch is then drawn in a neutral colour.

const HEX_COLOR = /^#[0-9A-Fa-f]{6}$/;

/** The colour when it is exactly #RRGGBB (6 hexadecimal digits), otherwise null. */
export function swatchColor(value: unknown): string | null {
  return typeof value === 'string' && HEX_COLOR.test(value) ? value : null;
}
