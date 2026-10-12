// Data for DisclosureOptionsExplainer: one salary disclosed six ways. Carol's salary and the
// threshold are made up for the illustration (the payroll demo pays Carol 5,000).

export const SALARY = 5_000;
export const OTHER_SALARY = 4_200; // Dave, for the payroll total in "split trust"
export const THRESHOLD = 3_000;

export type Seen = { kind: 'value' | 'proof' | 'sealed' | 'none'; text: string };

export type Option = {
  id: string;
  label: string;
  tech: string;
  href: string;
  summary: string;
  carol: Seen;
  landlord: Seen;
  tax: Seen;
  everyone: Seen;
  needs: string;
  onchain: string;
  maturity: string;
};

const n = (x: number) => x.toLocaleString('en-US');

export const OPTIONS: Option[] = [
  {
    id: 'reveal',
    label: 'Reveal the value',
    tech: 'BBS',
    href: '/selective-disclosure/reveal-attributes/',
    summary:
      'The employer signs a credential once. Carol shows the landlord only the salary line and hides the rest, and the landlord checks the employer signed it.',
    carol: { kind: 'value', text: `holds the signed credential (salary ${n(SALARY)}, name, role, …)` },
    landlord: { kind: 'value', text: `salary = ${n(SALARY)}, signed by the employer` },
    tax: { kind: 'none', text: 'not involved' },
    everyone: { kind: 'none', text: 'nothing; revealed values become public only if the presentation goes on-chain' },
    needs: 'An issuer with a BBS key. No circuit, no trusted setup.',
    onchain: 'BbsProofVerify, one fixed credential shape',
    maturity: 'Beta (IRTF draft)',
  },
  {
    id: 'rule',
    label: 'Prove a rule',
    tech: 'Groth16 predicate',
    href: '/selective-disclosure/prove-a-rule/',
    summary:
      'Carol proves a statement about her signed salary, such as "at least 3,000", without revealing the number. The landlord learns yes or no.',
    carol: { kind: 'value', text: `knows ${n(SALARY)}; runs the circuit on her device` },
    landlord: { kind: 'proof', text: `salary ≥ ${n(THRESHOLD)}: yes` },
    tax: { kind: 'none', text: 'not involved' },
    everyone: { kind: 'proof', text: `the proof and the threshold ${n(THRESHOLD)}` },
    needs: 'A circuit per question, and a trusted setup per circuit.',
    onchain: 'Groth16 verifier, about 2.1–2.5 billion steps, by public-input count',
    maturity: 'Beta',
  },
  {
    id: 'commit',
    label: 'Hide a number',
    tech: 'Pedersen commitment',
    href: '/selective-disclosure/hide-a-number/',
    summary:
      'The salary is published as a sealed commitment. Proofs show facts about it, and commitments add up, so totals can be checked without seeing any one salary.',
    carol: { kind: 'value', text: `knows ${n(SALARY)} and the blinding` },
    landlord: { kind: 'proof', text: `"the commitment hides at least ${n(THRESHOLD)}": yes` },
    tax: { kind: 'sealed', text: 'can add commitments up; learns a total only if given its opening' },
    everyone: { kind: 'sealed', text: 'a 32-byte commitment' },
    needs: 'A circuit for each statement about the value.',
    onchain: 'Commitment as two public inputs to a Groth16 proof',
    maturity: 'Ready (pending review) in-circuit; Experimental sums',
  },
  {
    id: 'readers',
    label: 'Tell chosen readers',
    tech: 'Confidential note',
    href: '/selective-disclosure/share-with-chosen-readers/',
    summary:
      'Next to the commitment, the opening is sealed on-chain for Carol and for the tax authority. Each one decrypts their own copy and checks it matches.',
    carol: { kind: 'value', text: `opens her delivery: ${n(SALARY)}` },
    landlord: { kind: 'none', text: 'nothing, unless Carol shares the opening' },
    tax: { kind: 'value', text: `opens its delivery: ${n(SALARY)}, if the sender delivered honestly (not enforced)` },
    everyone: { kind: 'sealed', text: 'the commitment + 89 bytes per reader' },
    needs: 'A viewing key per reader. No circuit for delivery itself.',
    onchain: 'Deliveries in the datum; only their length is checked',
    maturity: 'Experimental',
  },
  {
    id: 'auditor',
    label: 'Encrypt for an auditor',
    tech: 'ElGamal + proof',
    href: '/selective-disclosure/encrypt-for-an-auditor/',
    summary:
      "The salary is also encrypted to the tax authority's key, and a proof shows the ciphertext holds the same amount as the commitment. The employer can't under-report.",
    carol: { kind: 'value', text: `knows ${n(SALARY)}` },
    landlord: { kind: 'none', text: 'not involved' },
    tax: { kind: 'value', text: `decrypts ${n(SALARY)}, guaranteed to match the commitment` },
    everyone: { kind: 'sealed', text: 'commitment, ciphertext and proof' },
    needs: 'An auditor key with a possession proof, and a circuit.',
    onchain: 'Groth16 proof binds the ciphertext to the commitment',
    maturity: 'Experimental',
  },
  {
    id: 'threshold',
    label: 'Split the trust',
    tech: 'Threshold ElGamal',
    href: '/selective-disclosure/split-trust/',
    summary:
      'Salaries are encrypted to a key no one holds. Any 2 of 3 trustees together can decrypt; by policy they decrypt only the agreed result, here the payroll total. A quorum could decrypt one salary, so pick independent trustees.',
    carol: { kind: 'value', text: `knows ${n(SALARY)}` },
    landlord: { kind: 'none', text: 'not involved' },
    tax: { kind: 'proof', text: `2 of 3 trustees decrypt the total: ${n(SALARY + OTHER_SALARY)}` },
    everyone: { kind: 'sealed', text: 'ciphertexts, then the total once decrypted' },
    needs: 'A key generation ceremony among the trustees.',
    onchain: 'Ciphertexts in datums; ballot-style proofs',
    maturity: 'Experimental',
  },
];

// "Help me choose": each answer either asks another question or picks an option.
export type Choice = { text: string; next?: string; pick?: string };
export type Question = { id: string; text: string; choices: Choice[] };

export const QUESTIONS: Question[] = [
  {
    id: 'exact',
    text: 'Does anyone need to learn the exact value?',
    choices: [
      { text: 'No, a yes/no answer is enough', next: 'later' },
      { text: 'Yes', next: 'who' },
    ],
  },
  {
    id: 'later',
    text: 'Does the value also need to live on-chain, to be added up or checked again later?',
    choices: [
      { text: 'No, just answer this one question', pick: 'rule' },
      { text: 'Yes, keep it sealed on-chain', pick: 'commit' },
    ],
  },
  {
    id: 'who',
    text: 'Who should learn it?',
    choices: [
      { text: 'The verifier I am talking to', pick: 'reveal' },
      { text: 'Named parties, later, straight from the chain', pick: 'readers' },
      { text: "An authority, and the sender mustn't be able to lie", pick: 'auditor' },
      { text: 'No single party; only a group together', pick: 'threshold' },
    ],
  },
];
