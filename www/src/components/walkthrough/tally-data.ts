// Data for TallyWalkthrough, shared by its server render and its client script. Values follow the
// private-voting demo on zeroj-usecases PR #8 (ADR-0005): 3 trustees holding an n-of-n election key,
// and the README flow voter1 YES, voter2 NO, voter3 YES, then voter1 again (refused).
// Ciphertext and key strings are FNV stand-ins (fakeHash), not Jubjub points.
import { fakeHash } from './engine';

export const VOTERS = [
  { id: 'voter1', vote: 1 },
  { id: 'voter2', vote: 0 },
  { id: 'voter3', vote: 1 },
];

export const TRUSTEES = ['Trustee 1', 'Trustee 2', 'Trustee 3'];

// The ciphertext label depends on the vote and a per-voter nonce, so flipping a vote changes it.
export const ballotLabel = (voter: string, vote: number) => fakeHash(`ballot:${voter}:${vote}`);
export const nullifierLabel = (voter: string) => fakeHash(`nullifier:${voter}:dao-proposal-1`);
export const sumLabel = (votes: number[]) => fakeHash(`sum:${votes.join('')}`);
export const shareLabel = (trustee: string, votes: number[]) => fakeHash(`share:${trustee}:${votes.join('')}`);

export const yesCount = (votes: number[]) => votes.reduce((s, v) => s + v, 0);
