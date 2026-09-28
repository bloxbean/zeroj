// Data for ReservesWalkthrough, shared by its server render and its client script.
// Values follow the zeroj-usecases proof-of-reserves demo: the eight accounts seeded by
// AccountService.init(), zk.tree-depth 4 (16 slots, unused ones padded with balance 0) in
// application.yml, and `./demo.sh proof-of-reserves --run`, which proves against 10,000 ADA.

export const ACCOUNTS = [
  { id: 'alice', name: 'Alice', ada: 500 },
  { id: 'bob', name: 'Bob', ada: 1_200 },
  { id: 'charlie', name: 'Charlie', ada: 300 },
  { id: 'diana', name: 'Diana', ada: 2_500 },
  { id: 'eve', name: 'Eve', ada: 800 },
  { id: 'frank', name: 'Frank', ada: 150 },
  { id: 'grace', name: 'Grace', ada: 3_000 },
  { id: 'henry', name: 'Henry', ada: 50 },
];

export const TREE_DEPTH = 4;
export const SLOTS = 1 << TREE_DEPTH;
export const TOTAL_LIABILITIES = ACCOUNTS.reduce((sum, a) => sum + a.ada, 0);
export const DECLARED_RESERVES = 10_000;
export const RESERVE_RANGE = { min: 6_000, max: 12_000, step: 500 };

export const ada = (n: number) => `${n.toLocaleString('en-US')} ADA`;

// The circuit proves isSolvent == (totalReserves >= totalLiabilities); the validator requires 1.
export const isSolvent = (reserves: number) => reserves >= TOTAL_LIABILITIES;
