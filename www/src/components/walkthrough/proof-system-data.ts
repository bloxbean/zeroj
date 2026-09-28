// Facts and the recommendation rule for ProofSystemExplainer (learn/proof-systems), shared by its
// server render and its client script. Every fact restates the page's "Side by side" table or its
// sections; PlonK is never recommended (it is experimental in ZeroJ, with no correctness claims).

export type Need = 'compute' | 'reveal' | 'both';
export type Setup = 'ceremony' | 'universal';
export type Where = 'cardano' | 'offchain';
export type Answers = { need: Need; setup: Setup; where: Where };

export const DEFAULT_ANSWERS: Answers = { need: 'compute', setup: 'ceremony', where: 'cardano' };

type SystemId = 'groth16' | 'bbs' | 'plonk';

type Facts = { name: string; setup: string; size: string; verify: string; status: string };

const FACTS: Record<SystemId, Facts> = {
  groth16: {
    name: 'Groth16',
    setup: 'Trusted, per circuit: a shared phase 1 plus a phase 2 for each circuit',
    size: '192 bytes',
    verify: 'Lowest: one pairing check plus one multiplication per public input',
    status: 'Beta off-chain; Beta, testnet only on-chain',
  },
  bbs: {
    name: 'BBS',
    setup: 'None: the issuer just makes a key pair',
    size: '272 bytes + 32 per hidden attribute',
    verify: 'Pairing-based; grows with the attributes',
    status: 'Verification Beta; issuance Beta with a caveat',
  },
  plonk: {
    name: 'PlonK',
    setup: 'Trusted, universal: one setup reused across circuits',
    size: 'about 650 bytes',
    verify: 'Higher: two pairings and more multiplications',
    status: 'Experimental, off-chain and on-chain',
  },
};

type Note = { kind: 'ok' | 'warn'; html: string };
type Link = { href: string; label: string };
type Recommendation = { title: string; why: string; systems: SystemId[]; notes: Note[]; links: Link[] };

export function recommend(a: Answers): Recommendation {
  const notes: Note[] = [];
  const circuit = a.need !== 'reveal';

  if (circuit) {
    notes.push(
      a.setup === 'ceremony'
        ? { kind: 'ok', html: 'Plan a multi-party ceremony: phase 1 is shared, phase 2 runs once per circuit and again whenever the circuit changes.' }
        : { kind: 'warn', html: "Groth16 needs a phase-2 ceremony for each circuit. PlonK's universal setup avoids that, but PlonK is experimental in ZeroJ: research only, never anything that matters." },
    );
  }
  if (a.need !== 'compute') {
    notes.push({ kind: 'ok', html: 'BBS needs no trusted setup: the issuer just generates a key pair.' });
  }
  if (a.where === 'cardano') {
    if (circuit) {
      notes.push({ kind: 'ok', html: 'Groth16 on Cardano is Beta, testnet only. In ZeroJ\u2019s JuLC VM tests, a proof with two public inputs used about 2.8 billion of the 10 billion CPU units a transaction may spend.' });
    }
    if (a.need !== 'compute') {
      notes.push({ kind: 'warn', html: 'On-chain BBS supports one fixed shape: a 5-attribute credential revealing indexes 2 and 3. Other shapes need a different unrolling, or a Groth16 circuit.' });
    }
  } else {
    notes.push({ kind: 'ok', html: 'Off-chain, ZeroJ verifies in pure Java inside your service.' });
  }

  if (a.need === 'compute') {
    return {
      title: 'Groth16 on BLS12-381',
      why: "A yes/no answer computed from hidden values needs a circuit. Groth16 is ZeroJ's default: the smallest proofs and the cheapest check.",
      systems: ['groth16'],
      notes,
      links: [
        { href: '/guides/proving/groth16/', label: 'Prove with Groth16' },
        { href: '/learn/trusted-setup/', label: 'Trusted setup, explained' },
      ],
    };
  }
  if (a.need === 'reveal') {
    notes.push({ kind: 'warn', html: 'BBS reveals values; it can\'t prove a rule about a hidden one, such as "born before 2007". For that, add a circuit.' });
    return {
      title: 'BBS',
      why: 'You only show some signed attributes as they were issued. BBS needs no circuit and no trusted setup, and hidden attributes stay hidden.',
      systems: ['bbs'],
      notes,
      links: [
        { href: '/guides/credentials/bbs/', label: 'BBS credentials' },
        { href: '/use-cases/selective-disclosure/', label: 'Selective disclosure use case' },
      ],
    };
  }
  notes.push({ kind: 'warn', html: 'The circuit must also know the attribute came from the issuer, for example by checking an issuer signature inside the circuit.' });
  return {
    title: 'BBS + a Groth16 circuit',
    why: 'Reveal the attributes that can be shown as they are with BBS, and prove the rule about a hidden one with a small Groth16 circuit.',
    systems: ['bbs', 'groth16'],
    notes,
    links: [
      { href: '/use-cases/selective-disclosure/', label: 'Selective disclosure use case' },
      { href: '/guides/proving/groth16/', label: 'Prove with Groth16' },
    ],
  };
}

const factsCard = (id: SystemId) => {
  const f = FACTS[id];
  return `<dl class="zps-facts">
    <dt>Setup</dt><dd>${f.setup}</dd>
    <dt>Proof size</dt><dd>${f.size}</dd>
    <dt>Checking it</dt><dd>${f.verify}</dd>
    <dt>In ZeroJ</dt><dd>${f.status}</dd>
  </dl>`;
};

// HTML for the result card. Only static strings from this module go into it.
export function renderResult(a: Answers): string {
  const r = recommend(a);
  const facts = r.systems
    .map((id) => `<div class="zps-sys"><span class="zps-sys-name">${FACTS[id].name}</span>${factsCard(id)}</div>`)
    .join('');
  const notes = r.notes
    .map((n) => `<span class="zw-check${n.kind === 'warn' ? ' warn' : ''}">${n.html}</span>`)
    .join('');
  const links = r.links.map((l) => `<a href="${l.href}">${l.label} →</a>`).join('');
  return `<p class="zps-pick-label">Use</p>
    <p class="zps-pick">${r.title}</p>
    <p class="zps-why">${r.why}</p>
    <div class="zps-sys-list">${facts}</div>
    <div class="zps-notes">${notes}</div>
    <div class="zps-links">${links}</div>`;
}

export const PLONK_NOTE = `${FACTS.plonk.name}: ${FACTS.plonk.status.toLowerCase()}. Evaluation and research only.`;
