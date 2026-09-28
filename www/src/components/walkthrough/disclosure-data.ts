// Data and rules for DisclosureWalkthrough, shared by its server render and its client script.
// Values follow the zeroj-usecases demos: reusable-kyc (BBS) and selective-disclosure (Groth16),
// whose application.yml sets credential.current-year to 2026.

export const BBS_ATTRIBUTES = [
  { name: 'givenName', value: 'Alice Example' },
  { name: 'dob', value: '1990-05-01' },
  { name: 'country', value: 'USA' },
  { name: 'kycLevel', value: 'verified' },
  { name: 'docHash', value: '0x7d2e…a91c' },
];

// The verifier's policy needs these two, and the on-chain BbsProofVerify profile is fixed to
// disclosing exactly indexes 2 and 3.
export const BBS_REQUIRED = [2, 3];

export const CURRENT_YEAR = 2026;
export const APPROVED_COUNTRIES = [840, 826, 276, 250, 392]; // USA, UK, Germany, France, Japan
export const DOCTOR_ROLE_ID = 1001;

export type Holder = {
  id: string;
  name: string;
  dobYear: number;
  country: number;
  countryName: string;
  roleId: number;
  role: string;
  salaryBracket: number;
};

export const HOLDERS: Holder[] = [
  { id: 'alice', name: 'Alice', dobYear: 1995, country: 840, countryName: 'USA', roleId: 2001, role: 'engineer', salaryBracket: 5 },
  { id: 'bob', name: 'Bob', dobYear: 1990, country: 276, countryName: 'Germany', roleId: 1001, role: 'doctor', salaryBracket: 4 },
  { id: 'charlie', name: 'Charlie', dobYear: 2010, country: 826, countryName: 'UK', roleId: 9001, role: 'student', salaryBracket: 0 },
];

export type GateResult = { ok: boolean; why: string };

// AdultResidentProof: born no later than currentYear - 21, and country in the approved-country tree.
export function adultResident(h: Holder): GateResult {
  const maxDob = CURRENT_YEAR - 21;
  if (h.dobYear > maxDob) return { ok: false, why: `born ${h.dobYear}, must be ${maxDob} or earlier` };
  if (!APPROVED_COUNTRIES.includes(h.country)) return { ok: false, why: `country ${h.country} isn't approved` };
  return { ok: true, why: `born ${h.dobYear}, ${h.countryName} is approved` };
}

// SeniorDoctorProof: role is doctor, and born no later than currentYear - 30.
export function seniorDoctor(h: Holder): GateResult {
  const maxDob = CURRENT_YEAR - 30;
  if (h.roleId !== DOCTOR_ROLE_ID) return { ok: false, why: `role is ${h.role}, not doctor` };
  if (h.dobYear > maxDob) return { ok: false, why: `born ${h.dobYear}, must be ${maxDob} or earlier` };
  return { ok: true, why: `doctor, born ${h.dobYear}` };
}
