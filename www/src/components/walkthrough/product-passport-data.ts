// Data and rules for ProductPassportWalkthrough, shared by its server render and its client script.
// Values follow the zeroj-usecases digital-product-passport demo: ProductService.createDemoData()
// (battery packs) and application.yml (dpp.carbon-threshold-kg: 50, dpp.recycled-threshold-pct: 30).

export const CARBON_MAX_KG = 50;
export const RECYCLED_MIN_PCT = 30;
export const MANUFACTURER = 'BatteryAssembly GmbH';

export type Battery = { id: string; short: string; name: string; carbonKg: number; recycledPct: number };

export const BATTERIES: Battery[] = [
  { id: 'BAT-SN001', short: 'SN001', name: 'EV Battery Pack Alpha', carbonKg: 7, recycledPct: 45 },
  { id: 'BAT-SN002', short: 'SN002', name: 'EV Battery Pack Beta', carbonKg: 12, recycledPct: 38 },
  { id: 'BAT-SN003', short: 'SN003', name: 'EV Battery Pack Gamma (High Carbon)', carbonKg: 65, recycledPct: 20 },
];

// isCompliant is proven equal to the comparison, so a failing measurement proves isCompliant = 0.
export function claims(b: Battery): { carbon: boolean; recycled: boolean } {
  return { carbon: b.carbonKg <= CARBON_MAX_KG, recycled: b.recycledPct >= RECYCLED_MIN_PCT };
}

// The demo mints with the carbon claim's proof and public inputs in the datum; DppMintingPolicy
// requires isCompliant == 1.
export function canMint(b: Battery): boolean {
  return claims(b).carbon;
}
