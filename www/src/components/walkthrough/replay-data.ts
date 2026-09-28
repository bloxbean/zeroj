// Rules for ReplayExplainer, shared by its server render and its client script. Each outcome follows
// the "Replay and front-running" and "Nullifiers" sections of guides/verifying/application-security.

export type Guards = { spend: boolean; recipient: boolean; nullifier: boolean; nonce: boolean };
export type Outcome = { state: 'ok' | 'bad' | 'warn'; text: string };

export const GUARDS: { id: keyof Guards; name: string; how: string }[] = [
  {
    id: 'spend',
    name: 'Bind to the spend',
    how: 'A public input, spendRef, is computed by the validator from the UTxO being spent.',
  },
  {
    id: 'recipient',
    name: 'Bind the recipient',
    how: 'The recipient is in the statement, and the validator checks the outputs pay them.',
  },
  {
    id: 'nullifier',
    name: 'Store and check the nullifier',
    how: 'Poseidon(secret, scope) is public; spent nullifiers are stored and checked.',
  },
  {
    id: 'nonce',
    name: 'Single-use nonce (off-chain API)',
    how: 'Your service puts a random nonce in the statement and consumes it on first use.',
  },
];

export const ATTACKS = [
  { id: 'replay', name: 'Replay it later', where: 'API', does: 'Sends the same proof to your service again.' },
  {
    id: 'frontrun',
    name: 'Front-run: pay me instead',
    where: 'Cardano',
    does: 'Copies the redeemer into a transaction that spends the same UTxO but pays the attacker.',
  },
  { id: 'other', name: 'Use it on another UTxO', where: 'Cardano', does: 'Unlocks a different UTxO at the same script with the same proof.' },
  {
    id: 'twice',
    name: 'Claim twice with the same secret',
    where: 'Both',
    does: 'Alice, or anyone holding her secret, makes a fresh proof and claims again.',
  },
] as const;

export type AttackId = (typeof ATTACKS)[number]['id'];

export function outcome(id: AttackId, g: Guards): Outcome {
  switch (id) {
    case 'replay':
      if (g.nonce) return { state: 'ok', text: 'Blocked: the nonce was used up by the first request.' };
      if (g.nullifier) return { state: 'ok', text: 'Blocked: the replay carries the same nullifier, which is already stored.' };
      return { state: 'bad', text: 'Works: nothing marks the proof as used, so it is accepted again.' };
    case 'frontrun':
      if (g.recipient)
        return { state: 'ok', text: 'Blocked: the proof names Alice as the recipient, and the outputs must pay her.' };
      if (g.spend)
        return { state: 'bad', text: 'Works: the proof is tied to this UTxO but not to who gets paid, so the copy pays the attacker.' };
      if (g.nullifier)
        return { state: 'bad', text: "Works: the copy spends the UTxO first and pays the attacker. Its nullifier is the one recorded, and Alice's transaction fails." };
      return { state: 'bad', text: 'Works: nothing in the statement says who gets paid.' };
    case 'other':
      if (g.spend) return { state: 'ok', text: "Blocked: spendRef comes from the UTxO being spent, so the proof only fits Alice's UTxO." };
      if (g.nullifier) return { state: 'ok', text: 'Blocked: both uses carry the same nullifier, so only one can be recorded.' };
      if (g.recipient)
        return { state: 'warn', text: 'Partly: a second UTxO unlocks, but it must still pay Alice. The attacker gains nothing, yet one proof was used twice.' };
      return { state: 'bad', text: 'Works: the proof isn’t tied to one UTxO, so it unlocks any UTxO at this script.' };
    case 'twice':
      if (g.nullifier) return { state: 'ok', text: 'Blocked: the same secret and scope give the same nullifier, and it is already stored.' };
      if (g.spend || g.recipient || g.nonce)
        return { state: 'bad', text: 'Works: a fresh proof can name a new UTxO, the right recipient and a new nonce. Only a nullifier notices it is the same member.' };
      return { state: 'bad', text: 'Works: nothing stops the same member from claiming again.' };
  }
}

export function summary(g: Guards): string {
  const blocked = ATTACKS.filter((a) => outcome(a.id, g).state === 'ok').length;
  if (blocked === 0)
    return 'No protection: every copy works, and the verifier still says “proof valid” each time. The math can’t tell a copy from the original.';
  if (blocked < ATTACKS.length)
    return `Blocked ${blocked} of ${ATTACKS.length}. Each protection stops different attacks, so a real application usually needs several.`;
  return 'All four blocked. None of these checks comes from the proof system: your validator or service adds them.';
}

// What the proof commits to, given the protections that are on.
export function statement(g: Guards): string[] {
  return [
    'eligible (Merkle root)',
    ...(g.spend ? ['spendRef (this UTxO)'] : []),
    ...(g.recipient ? ['recipient = Alice'] : []),
    ...(g.nullifier ? ['nullifier'] : []),
    ...(g.nonce ? ['nonce (API)'] : []),
  ];
}
