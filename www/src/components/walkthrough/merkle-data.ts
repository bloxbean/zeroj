// Data and tree logic for MerkleExplainer, shared by its server render and its client script.
// Follows tutorials/private-allowlist: leaf = Poseidon(nullifierKey, trapdoor), node =
// Poseidon(left, right), empty slots hold 0, path bit 0 = our node is the left child,
// nullifier = Poseidon(nullifierKey, eventId). The picture uses 8 slots (depth 3); the tutorial's
// tree has depth 4. Hash values are fakeHash stand-ins, not Poseidon outputs.
import { fakeHash } from './engine';

export const WIDTH = 8;
export const MEMBERS = 5; // the tutorial registers five members
export const TUTORIAL_MEMBER = 2; // Main.java proves as member #2

// BigInteger.valueOf(2026_09_01) and BigInteger.valueOf(2026_10_01) in Main.java
export const EVENTS = [
  { id: '20260901', label: 'Event 1' },
  { id: '20261001', label: 'Event 2' },
];

const node = (left: string, right: string) => fakeHash(`${left}|${right}`);

export const nullifierKey = (who: number | 'out') => fakeHash(`nullifierKey:${who}`);
export const trapdoor = (who: number | 'out') => fakeHash(`trapdoor:${who}`);
export const leafOf = (who: number | 'out') => fakeHash(`leaf:${nullifierKey(who)}:${trapdoor(who)}`);
export const nullifierOf = (who: number | 'out', eventId: string) =>
  fakeHash(`nullifier:${nullifierKey(who)}:${eventId}`);

/** levels[0] = leaves ... levels[3] = [root]. */
export function buildTree(): string[][] {
  const levels: string[][] = [
    Array.from({ length: WIDTH }, (_, i) => (i < MEMBERS ? leafOf(i) : '0')),
  ];
  while (levels[levels.length - 1].length > 1) {
    const below = levels[levels.length - 1];
    const up: string[] = [];
    for (let i = 0; i < below.length; i += 2) up.push(node(below[i], below[i + 1]));
    levels.push(up);
  }
  return levels;
}

export const TREE = buildTree();
export const ROOT = TREE[TREE.length - 1][0];

export function nodeName(level: number, index: number): string {
  if (level === 0) return `L${index}`;
  if (level === 1) return `h${index}`;
  if (level === 2) return `h${2 * index}${2 * index + 1}`;
  return 'root';
}

export type PathStep = { level: number; index: number; name: string; value: string; bit: number };

/** The siblings from the leaf level up to (not including) the root, with their path bits. */
export function pathOf(leafIndex: number): PathStep[] {
  const out: PathStep[] = [];
  let index = leafIndex;
  for (let level = 0; level < TREE.length - 1; level++) {
    const sibling = index ^ 1;
    out.push({ level, index: sibling, name: nodeName(level, sibling), value: TREE[level][sibling], bit: index & 1 });
    index >>= 1;
  }
  return out;
}

/** Hash a leaf up a path: bit 0 -> hash(current, sibling), bit 1 -> hash(sibling, current). */
export function recompute(leaf: string, path: PathStep[]): string {
  return path.reduce((current, step) => (step.bit === 0 ? node(current, step.value) : node(step.value, current)), leaf);
}
