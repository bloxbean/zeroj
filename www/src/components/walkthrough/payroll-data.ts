// Data for PayrollWalkthrough, shared by its server render and its client script. Values follow the
// zeroj-usecases pedersen-commitments payroll tab (zeroj-usecases PR #9): the UI pays carol 5,000,
// the DevKit E2E pays carol 5,000 and dave 4,200 in one pay run and carol transfers 800 to dave; the
// UI's cash-out default is 1,000, and the under-report cheat tells the tax authority 3,000.

export const CAROL_SALARY = 5_000;
export const DAVE_SALARY = 4_200;
export const TRANSFER = 800;
export const CASH_OUT = 1_000;
export const REPORTED_DEFAULT = 3_000;

export const credits = (n: number) => n.toLocaleString('en-US');

// NoteIssueProof exists only if every note's two 32-bit limbs, encrypted to the tax authority,
// recombine to the amount the note's commitment hides.
export const issueProofExists = (reported: number) => reported === CAROL_SALARY;
