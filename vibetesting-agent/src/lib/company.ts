/**
 * Same legal entity as the rest of the business — VibeTesting Agent is a product line, not a new company.
 * Update LEGAL_NAME if your ABN entity name differs.
 */
export const COMPANY = {
  legalName: process.env.NEXT_PUBLIC_LEGAL_NAME || 'Newsengine',
  productName: 'VibeTesting Agent',
  productDomain: 'vibetestingagent.com',
  supportEmail: process.env.NEXT_PUBLIC_SUPPORT_EMAIL || 'mike@dynamicbusiness.com.au',
  abn: process.env.NEXT_PUBLIC_ABN || '', // optional
} as const;

export function providedByLine(): string {
  return `${COMPANY.productName} is a product of ${COMPANY.legalName}.`;
}
