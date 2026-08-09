# Stripe products (live)

Account: `acct_1SW2BE2Aw6uDXs2h` — **Vibe Testing Agent** / Indefatigable Media Pty Ltd  
Dashboard: https://dashboard.stripe.com  

Checkout also forces `branding_settings.display_name = VibeTesting Agent` in `src/lib/stripe.ts`.

| Plan | Amount | Product | Price ID |
|---|---|---|---|
| Weekly | $25/mo | `prod_Uzml4qe3k7dCd3` | `price_1TznCQ2Aw6uDXs2h6IObHOpA` |
| Daily | $100/mo | `prod_UzmlIcItJVOmLc` | `price_1TznCR2Aw6uDXs2ha3ikHUTT` |
| Every commit | $250/mo | `prod_UzmlNSMrkfk2yc` | `price_1TznCR2Aw6uDXs2hQIFEXyGW` |

Lookup keys: `weekly`, `daily`, `commit`

Webhook: `https://vibetestingagent.com/api/webhooks/stripe` (`we_1TznCS2Aw6uDXs2h6Y6oRVjc`)

Founder coupon (server-side only, FOUNDER_BILLING_EMAILS): `faMmf4Il` — $249 off first commit invoice → $1.

**Do not use** account `acct_1TUMknPUPbERFTLL` (retired / incorrect for this product).
