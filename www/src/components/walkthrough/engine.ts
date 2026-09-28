// Step engine for the use-case walkthroughs (VotingWalkthrough, DisclosureWalkthrough).
//
// Markup contract, all inside one `.zw` root:
//   data-total="N"                 number of steps on the root
//   [data-goto="n"]                step buttons in the step list
//   [data-prev] [data-next]        previous / next buttons
//   [data-play]                    autoplay toggle (aria-pressed)
//   [data-view-btn="name"]         view switch; sets root[data-view]
//   [data-present]                 fullscreen toggle for the enclosing `.zw-frame`
//   [data-show="1,3-5"]            element shown only on those steps (data-off otherwise)
//   [data-hl="2"] / [data-bad="4"] element highlighted / marked failing on those steps
// Per-step styling beyond that is plain CSS on `.zw[data-step="n"]`.

type StepSets = { show?: Set<number>; hl?: Set<number>; bad?: Set<number> };

const AUTOPLAY_MS = 5200;

function parseSteps(spec: string | undefined): Set<number> | undefined {
  if (!spec) return undefined;
  const steps = new Set<number>();
  for (const part of spec.split(',')) {
    const [from, to] = part.split('-').map((n) => Number(n.trim()));
    for (let i = from; i <= (to || from); i++) steps.add(i);
  }
  return steps;
}

export function initWalkthrough(root: HTMLElement): { go: (n: number) => void } {
  const total = Number(root.dataset.total) || 1;
  const frame = root.closest<HTMLElement>('.zw-frame') ?? root;
  const sets = new Map<HTMLElement, StepSets>();
  root.querySelectorAll<HTMLElement>('[data-show],[data-hl],[data-bad]').forEach((el) =>
    sets.set(el, {
      show: parseSteps(el.dataset.show),
      hl: parseSteps(el.dataset.hl),
      bad: parseSteps(el.dataset.bad),
    }),
  );
  const gotoButtons = [...root.querySelectorAll<HTMLButtonElement>('[data-goto]')];
  const prev = root.querySelector<HTMLButtonElement>('[data-prev]');
  const next = root.querySelector<HTMLButtonElement>('[data-next]');
  const play = root.querySelector<HTMLButtonElement>('[data-play]');
  const counter = root.querySelector<HTMLElement>('[data-counter]');
  let step = 1;
  let timer: number | undefined;

  const stop = () => {
    window.clearInterval(timer);
    timer = undefined;
    play?.setAttribute('aria-pressed', 'false');
  };

  const go = (n: number) => {
    step = Math.min(Math.max(n, 1), total);
    root.dataset.step = String(step);
    sets.forEach((s, el) => {
      if (s.show) el.toggleAttribute('data-off', !s.show.has(step));
      if (s.hl) el.toggleAttribute('data-hl-on', s.hl.has(step));
      if (s.bad) el.toggleAttribute('data-bad-on', s.bad.has(step));
    });
    gotoButtons.forEach((b) => {
      const on = Number(b.dataset.goto) === step;
      if (on) b.setAttribute('aria-current', 'step');
      else b.removeAttribute('aria-current');
    });
    if (prev) prev.disabled = step === 1;
    if (next) next.disabled = step === total;
    if (counter) counter.textContent = `${step} / ${total}`;
    root.dispatchEvent(new CustomEvent('zw:step', { detail: step }));
  };

  gotoButtons.forEach((b) => b.addEventListener('click', () => (stop(), go(Number(b.dataset.goto)))));
  prev?.addEventListener('click', () => (stop(), go(step - 1)));
  next?.addEventListener('click', () => (stop(), go(step + 1)));
  play?.addEventListener('click', () => {
    if (timer) return stop();
    if (step === total) go(1);
    play.setAttribute('aria-pressed', 'true');
    timer = window.setInterval(() => (step < total ? go(step + 1) : stop()), AUTOPLAY_MS);
  });

  root.querySelectorAll<HTMLButtonElement>('[data-view-btn]').forEach((b, _, all) =>
    b.addEventListener('click', () => {
      root.dataset.view = b.dataset.viewBtn;
      all.forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
    }),
  );

  root.querySelectorAll<HTMLButtonElement>('[data-present]').forEach((b) =>
    b.addEventListener('click', () => {
      if (document.fullscreenElement) document.exitFullscreen?.();
      else frame.requestFullscreen?.().catch(() => {});
    }),
  );
  document.addEventListener('fullscreenchange', () => {
    const on = document.fullscreenElement === frame;
    root.querySelectorAll('[data-present]').forEach((b) => {
      b.setAttribute('aria-pressed', String(on));
      b.textContent = on ? 'Exit' : 'Present';
    });
  });

  // Arrow keys step through while focus is anywhere inside the walkthrough (presenter clickers send
  // arrows or PageUp/PageDown).
  root.addEventListener('keydown', (e) => {
    if ((e.target as HTMLElement).closest('input, select, textarea')) return;
    if (e.key === 'ArrowRight' || e.key === 'PageDown') (stop(), go(step + 1));
    else if (e.key === 'ArrowLeft' || e.key === 'PageUp') (stop(), go(step - 1));
    else return;
    e.preventDefault();
  });

  go(1);
  return { go };
}

// Short, stable stand-in for a hash, so the illustration shows distinct values that change when the
// inputs change. Illustrative only: it is FNV-1a, not Poseidon.
export function fakeHash(input: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ (c + i), 0x811c9dc5) >>> 0;
  }
  const hex = (h1.toString(16).padStart(8, '0') + h2.toString(16).padStart(8, '0'));
  return `0x${hex.slice(0, 4)}…${hex.slice(-4)}`;
}

export function randomHex(bytes: number): string {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  const hex = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  return `0x${hex.slice(0, 4)}…${hex.slice(-4)}`;
}
