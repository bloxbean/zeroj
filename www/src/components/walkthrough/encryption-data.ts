// Data for EncryptionExplainer. Amounts are made up for the illustration; ciphertext strings are
// FNV stand-ins (fakeHash), not curve points.
import { fakeHash } from './engine';

export const SENDERS = [
  { name: 'Alice', amount: 4_200, nonce: 101 },
  { name: 'Bob', amount: 2_500, nonce: 202 },
];

export const TRUSTEES = ['Trustee 1', 'Trustee 2', 'Trustee 3'];
export const THRESHOLD = 2;

export const fmt = (n: number) => n.toLocaleString('en-US');

export const ctLabel = (amount: number, nonce: number) => fakeHash(`ct:${amount}:${nonce}`);
