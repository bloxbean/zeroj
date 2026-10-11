// Data and rules for AuctionWalkthrough, shared by its server render and its client script.
// Values follow the zeroj-usecases sealed-bid auction demo (pedersen-commitments, PR #9): lot
// "Painting", a common deposit of 100 ADA, a reserve of 10 ADA, and AuctionDevKitE2ETest's bids
// alice 40, bob 70, carol 70 (bob wins at 70 as the earlier of the two highest bids).

export const ITEM = 'Painting';
export const DEPOSIT = 100;
export const RESERVE = 10;
export const BID_RANGE = { min: 0, max: 120, step: 5 };

export type Bidder = { id: string; name: string; bid: number };

export const BIDDERS: Bidder[] = [
  { id: 'alice', name: 'Alice', bid: 40 },
  { id: 'bob', name: 'Bob', bid: 70 },
  { id: 'carol', name: 'Carol', bid: 70 },
];

export const ada = (n: number) => `${n.toLocaleString('en-US')} ADA`;

// BidProof: a proof exists only for reserve <= bid <= deposit, so other bids never reach the lot.
export const bidOk = (bid: number) => bid >= RESERVE && bid <= DEPOSIT;

export type Settlement =
  | { kind: 'none' }
  | { kind: 'win'; winner: number; price: number; cheat: { bidder: number; price: number } };

// SettleProof: first price, the earliest highest bid wins. `bids` are in lot (datum) order; an
// out-of-range bid was refused at bid time, so it isn't in the lot. The cheat is a claim the
// auctioneer can't prove: the best other accepted bid at its own amount (with a tie, the later
// equal bid, as in the demo's cheat), or else a lower price.
export function settle(bids: number[]): Settlement {
  const accepted = bids.map((b, i) => ({ b, i })).filter((x) => bidOk(x.b));
  if (accepted.length === 0) return { kind: 'none' };
  let best = accepted[0];
  for (const x of accepted) if (x.b > best.b) best = x;
  let other: { b: number; i: number } | undefined;
  for (const x of accepted) if (x.i !== best.i && (!other || x.b > other.b)) other = x;
  const cheat = other ? { bidder: other.i, price: other.b } : { bidder: best.i, price: best.b - 5 };
  return { kind: 'win', winner: best.i, price: best.b, cheat };
}
