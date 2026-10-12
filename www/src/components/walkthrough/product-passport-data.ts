// Data and rules for ProductPassportWalkthrough and PassportPrivacyExplainer, shared by their server
// render and client scripts. Values follow the zeroj-usecases digital-product-passport demo
// (ADR-0009 D1): ProductService.createDemoData() (battery packs), ApprovedSets (the 27 EU states,
// inspectors 11-15), application.yml (dpp.carbon-threshold-kg: 50, dpp.recycled-threshold-pct: 30),
// DppController.CHOSEN_THRESHOLD (65,535) and the constraint counts ClaimCircuitTest prints.

export const CARBON_MAX_KG = 50;
export const RECYCLED_MIN_PCT = 30;
export const MANUFACTURER = 'BatteryAssembly GmbH';
// What "Skip off-chain check" proves against when no carbon proof for <= 50 kg exists.
export const CHOSEN_THRESHOLD = 65_535;
// The old design's auditor key, a prover input hard-coded in the demo source.
export const OLD_AUDITOR_SECRET = 777_777;

const EU_COUNTRIES = new Set([
  40, 56, 100, 191, 196, 203, 208, 233, 246, 250, 276, 300, 348, 372, 380, 428, 440, 442, 470, 528, 616,
  620, 642, 703, 705, 724, 752,
]);
const INSPECTORS = new Set([11, 12, 13, 14, 15]);

export type Battery = {
  id: string;
  short: string;
  name: string;
  carbonKg: number;
  recycledPct: number;
  country: number; // ISO 3166-1 numeric; 276 = Germany
  inspectors: number[]; // three checkpoints, times strictly increasing in the demo data
};

export const BATTERIES: Battery[] = [
  { id: 'BAT-SN001', short: 'SN001', name: 'EV Battery Pack Alpha', carbonKg: 7, recycledPct: 45, country: 276, inspectors: [11, 13, 11] },
  { id: 'BAT-SN002', short: 'SN002', name: 'EV Battery Pack Beta', carbonKg: 12, recycledPct: 38, country: 276, inspectors: [12, 14, 15] },
  { id: 'BAT-SN003', short: 'SN003', name: 'EV Battery Pack Gamma (High Carbon)', carbonKg: 65, recycledPct: 20, country: 276, inspectors: [11, 12, 13] },
];

export type ClaimKey = 'carbon' | 'recycled' | 'origin' | 'inspections';

export const CLAIMS: { key: ClaimKey; id: number; circuit: string; rule: string; constraints: string }[] = [
  { key: 'carbon', id: 0, circuit: 'CarbonClaimProof', rule: `carbon ≤ ${CARBON_MAX_KG} kg`, constraints: '2,192' },
  { key: 'recycled', id: 1, circuit: 'RecycledClaimProof', rule: `recycled ≥ ${RECYCLED_MIN_PCT} %`, constraints: '2,192' },
  { key: 'origin', id: 2, circuit: 'OriginClaimProof', rule: 'made in the EU', constraints: '3,344' },
  { key: 'inspections', id: 3, circuit: 'InspectionClaimProof', rule: '3 approved inspections, in order', constraints: '5,094' },
];

// Every rule is an assertion: a claim that doesn't hold has no proof at all.
export function claims(b: Battery): Record<ClaimKey, boolean> {
  return {
    carbon: b.carbonKg <= CARBON_MAX_KG,
    recycled: b.recycledPct >= RECYCLED_MIN_PCT,
    origin: EU_COUNTRIES.has(b.country),
    inspections: b.inspectors.every((i) => INSPECTORS.has(i)),
  };
}

// Only carbon is gated on-chain: DppPassport verifies the carbon proof against its own threshold.
export function canMint(b: Battery): boolean {
  return claims(b).carbon;
}

export function measurement(b: Battery, key: ClaimKey): string {
  switch (key) {
    case 'carbon':
      return `${b.carbonKg} kg CO₂e`;
    case 'recycled':
      return `${b.recycledPct} %`;
    case 'origin':
      return b.country === 276 ? '276 (DEU)' : String(b.country);
    case 'inspections':
      return b.inspectors.join(', ');
  }
}
