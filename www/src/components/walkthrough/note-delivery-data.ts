// Data for NoteDeliveryExplainer, shared by its server render and its client script. The amount
// matches the guide's ConfidentialNoteDemo (250). Points and bytes are FNV stand-ins (fakeHash).
import { fakeHash } from './engine';

export const AMOUNT = 250;

export type Holder = 'owner' | 'auditor' | 'stranger';

export const HOLDERS: { id: Holder; label: string; position: number | null }[] = [
  { id: 'owner', label: 'Owner', position: 0 },
  { id: 'auditor', label: 'Auditor', position: 1 },
  { id: 'stranger', label: 'Stranger', position: null },
];

export const commitment = fakeHash(`note-C:${AMOUNT}`);
export const delivery = (position: number, garbage = false) =>
  garbage ? fakeHash(`random-89-bytes:${position}`) : fakeHash(`delivery:${position}:${AMOUNT}`);

// The wallet scan in step 5: notes at the ledger address, as the owner's wallet sees them.
export const SCAN = [
  { label: 'Note A', mine: true, opens: true, amount: AMOUNT },
  { label: 'Note B', mine: false, opens: false, amount: 0 },
  { label: 'Note C', mine: true, opens: true, amount: 40 },
  { label: 'Note D', mine: true, opens: false, amount: 0 },
];
