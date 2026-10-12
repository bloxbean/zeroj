// Data for CommitmentExplainer, shared by its server render and its client script. The amounts are
// made up for the illustration; the commitment strings are FNV stand-ins (fakeHash), not points.
import { fakeHash } from './engine';

export const ALICE = { amount: 4_200, blinding: 7_340_113, blinding2: 7_340_113 ^ 0x5bd1e995 };
export const BOB = { amount: 2_500, blinding: 1_928_377 };
export const MIN_DEPOSIT = 1_000;

export const fmt = (n: number) => `${n.toLocaleString('en-US')} ADA`;

// The same (amount, blinding) always gives the same label, and the sum step uses (a + b, r + s),
// so "C + D" and "commit(a + b, r + s)" print the same value, as they do for real commitments.
export const commitLabel = (amount: number, blinding: number) => fakeHash(`C:${amount}:${blinding}`);
