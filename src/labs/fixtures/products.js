/**
 * src/labs/fixtures/products.js — shared ShopSphere product catalog.
 *
 * Extracted from routes/vulns-business.js's inline CATALOG object (Phase 2
 * ShopSphere pass, see docs/UPGRADE-LOG.md) and enriched with realistic
 * display metadata (category, blurb) for the new storefront. The ids and
 * prices are UNCHANGED from the original — every checkout/coupon/refund
 * route's actual vulnerable logic keys off these same ids and prices, so
 * this is purely additive enrichment, not a behavior change.
 */
const PRODUCTS = {
  widget: { id: "widget", name: "Standard Widget", price: 49.99, category: "Hardware", blurb: "The one that started it all. Reliable, unassuming, gets the job done." },
  gadget: { id: "gadget", name: "Pro Gadget", price: 129.99, category: "Hardware", blurb: "For when the Standard Widget just isn't enough gadget." },
  "premium-support": { id: "premium-support", name: "Premium Support Plan", price: 999.0, category: "Services", blurb: "Priority response times and a dedicated account contact." },
};

function listProducts() {
  return Object.values(PRODUCTS);
}

module.exports = { PRODUCTS, listProducts };
