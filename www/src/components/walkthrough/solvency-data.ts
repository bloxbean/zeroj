// Data for SolvencyWalkthrough, shared by its server render and its client script. Values follow the
// zeroj-usecases pedersen-commitments demo C (SolvencyService defaults on the
// feat/confidential-notes-m3 branch): four customers, 2,000 ADA locked, a period that starts about
// 45 s after the attestation and lasts 180 s. Commitments and hashes are fakeHash stand-ins.

export const BOOK = [
  { id: 'alice', name: 'Alice', ada: 500 },
  { id: 'bob', name: 'Bob', ada: 1_200 },
  { id: 'carol', name: 'Carol', ada: 300 },
  { id: 'dave', name: 'Dave', ada: 0 },
];

export const TOTAL = BOOK.reduce((sum, c) => sum + c.ada, 0);
export const DEFAULT_RESERVE = 2_000;
export const RESERVE_RANGE = { min: 1_000, max: 3_000, step: 100 };
export const PERIOD = { leadSeconds: 45, lengthSeconds: 180 };
export const GARBAGE_DEFAULT = 'dave';

export const ada = (n: number) => `${n.toLocaleString('en-US')} ADA`;

// HiddenLiabilitySolvencyProof: Σ balances ≤ reserves. Below the book total no proof exists.
export const provable = (reserve: number) => TOTAL <= reserve;

export type Check = 'LISTED_ONCE_CORRECT' | 'UNOPENABLE';

// SolvencyAttestation.customerCheck, for the two outcomes the walkthrough can produce: an honest
// entry, or the "garbage delivery" cheat, which the vault accepts (it only checks the length).
export const customerCheck = (id: string, garbageFor: string | null): Check =>
  id === garbageFor ? 'UNOPENABLE' : 'LISTED_ONCE_CORRECT';
