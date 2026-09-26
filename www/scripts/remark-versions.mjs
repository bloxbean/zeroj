// Remark plugin: replaces %ZEROJ_VERSION%, %JULC_VERSION% and %CCL_VERSION% in text, inline code
// and code blocks. Runs before Expressive Code (a rehype plugin), so highlighted code gets the
// substituted value too.

import { replaceVersionTokens } from '../site.config.mjs';

function visit(node) {
  if (typeof node.value === 'string' && node.value.includes('%')) {
    node.value = replaceVersionTokens(node.value);
  }
  // Link targets can carry versions as well (for example a Maven Central URL).
  if (typeof node.url === 'string' && node.url.includes('%')) {
    node.url = replaceVersionTokens(node.url);
  }
  if (Array.isArray(node.children)) node.children.forEach(visit);
}

export default function remarkVersions() {
  return (tree) => visit(tree);
}
