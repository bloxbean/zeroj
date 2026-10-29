// Digests of the public 48-byte fixtures in www/examples/sha256-record.
// This diagram explains a checked Java example; it does not generate browser proofs.
export const recordCases = [
  { id: 'approved', label: 'Issued approval', subject: 'USER0042', status: '1 · approved',
    digest: 'e0dea9dc571d39771bfef376bd3fa167458246ee8a3492f1f3c601532a88e891',
    proof: 'Valid: hash and approval policy match', accepted: true, valid: true,
    why: 'The record satisfies the circuit, and its digest is the one the application trusts.' },
  { id: 'edited', label: 'Edit the record', subject: 'USER0043', status: '1 · approved',
    digest: 'e0dea9dc571d39771bfef376bd3fa167458246ee8a3492f1f3c601532a88e891',
    proof: 'Rejected: edited bytes have a different hash', accepted: false, valid: false,
    why: 'Changing the private subject while claiming the original digest breaks the hash constraint.' },
  { id: 'denied', label: 'Denied record', subject: 'USER0042', status: '0 · denied',
    digest: 'fc3c8bec5f71459550dd34dda8c368178f02f2ef9e4d903ae6d43f36911e7802',
    proof: 'Rejected: status must equal approved', accepted: false, valid: false,
    why: 'Even with its own correct digest, a denied record cannot satisfy the approval constraint.' },
  { id: 'other', label: 'Unregistered record', subject: 'USER0099', status: '1 · approved',
    digest: '850a1839abe125921dab3316b8cacca31a1f8d79deb104eaa104d69a28cc77af',
    proof: 'Valid: this different record is approved', accepted: false, valid: true,
    why: 'The math is true, but this digest is absent from the trusted registry. The application rejects it.' },
] as const;

export const shortDigest = (hex: string) => `${hex.slice(0, 8)}…${hex.slice(-8)}`;
