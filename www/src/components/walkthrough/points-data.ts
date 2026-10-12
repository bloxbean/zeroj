// Data for PointsWalkthrough. Values follow the zeroj-usecases pedersen-commitments demo, points tab
// (PR #9, branch feat/confidential-notes-m3): the retailer issues 1,000 to alice, alice transfers
// 700 to bob, bob redeems 120 at the retailer. The under-report cheat tells the auditor 100.
// Commitment strings are FNV stand-ins (fakeHash), not Jubjub points.
import { fakeHash } from './engine';

export type Note = {
  id: string;
  owner: 'Alice' | 'Bob';
  amount: number;
  createdAt: number; // step that creates the note
  spentAt?: number; // step that spends it (honest run)
  origin: 'issuer-claimed' | 'proof-enforced';
  how: string;
};

export const ISSUED = 1_000;
export const TRANSFERRED = 700;
export const PRICE = 120;
export const UNDER_REPORTED = 100;

export const NOTES: Note[] = [
  { id: 'N1', owner: 'Alice', amount: ISSUED, createdAt: 2, spentAt: 3, origin: 'issuer-claimed', how: 'issued by the retailer' },
  { id: 'N2', owner: 'Bob', amount: TRANSFERRED, createdAt: 3, spentAt: 4, origin: 'proof-enforced', how: 'transfer output' },
  { id: 'N3', owner: 'Alice', amount: ISSUED - TRANSFERRED, createdAt: 3, origin: 'proof-enforced', how: 'transfer change' },
  { id: 'N4', owner: 'Bob', amount: TRANSFERRED - PRICE, createdAt: 4, origin: 'proof-enforced', how: 'redeem change' },
];

export const pts = (n: number) => `${n.toLocaleString('en-US')} pts`;
export const commitment = (n: Note) => fakeHash(`note:${n.id}:${n.amount}`);
