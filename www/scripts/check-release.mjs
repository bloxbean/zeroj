// Checks www/release.json against Maven Central, so the docs never advertise a version users can't
// download or pair ZeroJ with the wrong JuLC / Cardano Client Lib:
//   - julc and ccl must exist on Central;
//   - once `released` is true, zeroj must exist too, and the published zeroj-onchain-julc POM must
//     depend on exactly the julc and ccl versions in release.json.
// Needs network. In CI (CI=true) a network failure fails the check; locally it only warns.
import { RELEASE } from '../site.config.mjs';

const CENTRAL = 'https://repo1.maven.org/maven2';
const pomUrl = (group, artifact, version) =>
  `${CENTRAL}/${group.replaceAll('.', '/')}/${artifact}/${version}/${artifact}-${version}.pom`;

const problems = [];
let offline = false;

async function fetchPom(group, artifact, version) {
  try {
    const res = await fetch(pomUrl(group, artifact, version));
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  } catch (e) {
    offline = true;
    console.warn(`check-release: could not reach Maven Central for ${artifact}:${version} (${e.message})`);
    return undefined;
  }
}

async function requirePublished(group, artifact, version, what) {
  const pom = await fetchPom(group, artifact, version);
  if (pom === null) problems.push(`${what}: ${group}:${artifact}:${version} is not on Maven Central`);
  return pom;
}

// JuLC moved from com.bloxbean.cardano to org.julclang in 0.1.0-pre17 (ADR-0050). Matching the group
// as well as the artifact keeps a ZeroJ POM still built against the old JuLC group from passing.
const JULC_GROUP = 'org.julclang';

function dependencyVersion(pom, group, artifact) {
  const m = pom.match(new RegExp(
    `<groupId>${group}</groupId>\\s*<artifactId>${artifact}</artifactId>\\s*<version>([^<]+)</version>`));
  return m?.[1];
}

await requirePublished(JULC_GROUP, 'julc-stdlib', RELEASE.julc, 'release.json "julc"');
await requirePublished('com.bloxbean.cardano', 'cardano-client-lib', RELEASE.ccl, 'release.json "ccl"');

if (RELEASE.released) {
  await requirePublished('org.zeroj', 'zeroj-bom-core', RELEASE.zeroj, 'release.json "zeroj"');
  const onchain = await requirePublished('org.zeroj', 'zeroj-onchain-julc', RELEASE.zeroj, 'release.json "zeroj"');
  if (onchain) {
    const julc = dependencyVersion(onchain, JULC_GROUP, 'julc-stdlib');
    const ccl = dependencyVersion(onchain, 'com.bloxbean.cardano', 'cardano-client-crypto');
    if (!julc) {
      problems.push(`ZeroJ ${RELEASE.zeroj}'s zeroj-onchain-julc POM has no ${JULC_GROUP}:julc-stdlib dependency`);
    } else if (julc !== RELEASE.julc) {
      problems.push(`release.json "julc" is ${RELEASE.julc}, but ZeroJ ${RELEASE.zeroj} was built with JuLC ${julc}`);
    }
    if (ccl && ccl !== RELEASE.ccl) {
      problems.push(`release.json "ccl" is ${RELEASE.ccl}, but ZeroJ ${RELEASE.zeroj} was built with CCL ${ccl}`);
    }
  }
} else {
  console.log(
    `check-release: "released" is false, so ZeroJ ${RELEASE.zeroj} is not checked on Maven Central ` +
      `(the Installation and Quickstart pages say it isn't published yet).`,
  );
}

if (problems.length) {
  console.error(`check-release: ${problems.length} problem(s):\n  - ${problems.join('\n  - ')}`);
  process.exit(1);
}
if (offline && process.env.CI) {
  console.error('check-release: Maven Central was unreachable; failing in CI.');
  process.exit(1);
}
console.log(
  `check-release: zeroj ${RELEASE.zeroj} (${RELEASE.released ? 'released' : 'not released yet'}), ` +
    `julc ${RELEASE.julc}, ccl ${RELEASE.ccl}${offline ? ' — some checks skipped (offline)' : ' verified'}.`,
);
