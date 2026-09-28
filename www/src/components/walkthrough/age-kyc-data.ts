// Data and rules for AgeKycWalkthrough, shared by its server render and its client script.
// Values follow the zeroj-usecases identity-kyc demo: IssuerService issues the five test credentials
// and builds the approved-country tree; application.yml sets min-age 18 and country-tree-depth 4.

export const MIN_AGE = 18;
export const COUNTRY_TREE_DEPTH = 4;

// Leaf order matches IssuerService.approvedCountries.
export const APPROVED = [
  { code: 840, iso: 'USA' },
  { code: 826, iso: 'GBR' },
  { code: 276, iso: 'DEU' },
  { code: 250, iso: 'FRA' },
  { code: 392, iso: 'JPN' },
];

export type Holder = { id: string; name: string; age: number; country: number; iso: string };

export const HOLDERS: Holder[] = [
  { id: 'alice', name: 'Alice', age: 25, country: 840, iso: 'USA' },
  { id: 'bob', name: 'Bob', age: 30, country: 826, iso: 'GBR' },
  { id: 'charlie', name: 'Charlie', age: 16, country: 840, iso: 'USA' },
  { id: 'diana', name: 'Diana', age: 22, country: 76, iso: 'BRA' },
  { id: 'eve', name: 'Eve', age: 45, country: 392, iso: 'JPN' },
];

export type Outcome = {
  leaf: number; // index in the approved-country tree, -1 if the country isn't a leaf
  canProve: boolean; // a Merkle path exists, so the circuit has a satisfying witness
  eligible: 0 | 1; // the circuit proves eligible == (age >= minAge)
  unlock: boolean; // the validator requires eligible == 1
};

export function evaluate(h: Holder): Outcome {
  const leaf = APPROVED.findIndex((c) => c.code === h.country);
  const eligible = h.age >= MIN_AGE ? 1 : 0;
  return { leaf, canProve: leaf >= 0, eligible, unlock: leaf >= 0 && eligible === 1 };
}
