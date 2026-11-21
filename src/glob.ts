/**
 * Deterministic polynomial-time glob matcher (two-pointer segment + character DP).
 * Compiles zero dynamic RegExp instances so untrusted globs in .mdc or .instructions.md
 * can never trigger catastrophic regex backtracking.
 */

const MAX_BRACE_EXPANSIONS = 16;

function normalizePosix(input: string): string {
  let out = input.replace(/\\/g, '/').trim();
  while (out.startsWith('./')) {
    out = out.slice(2);
  }
  while (out.startsWith('/')) {
    out = out.slice(1);
  }
  while (out.endsWith('/') && out.length > 1) {
    out = out.slice(0, -1);
  }
  return out;
}

function expandBraces(pattern: string): string[] {
  const results: string[] = [];
  const queue: string[] = [pattern];

  while (queue.length > 0 && results.length < MAX_BRACE_EXPANSIONS) {
    const current = queue.shift()!;
    const openIdx = current.indexOf('{');
    if (openIdx === -1) {
      results.push(current);
      continue;
    }
    const closeIdx = current.indexOf('}', openIdx + 1);
    if (closeIdx === -1) {
      results.push(current);
      continue;
    }
    const prefix = current.slice(0, openIdx);
    const body = current.slice(openIdx + 1, closeIdx);
    const suffix = current.slice(closeIdx + 1);
    const options = body.split(',');
    if (options.length <= 1) {
      results.push(prefix + body + suffix);
      continue;
    }
    for (const opt of options) {
      if (queue.length + results.length >= MAX_BRACE_EXPANSIONS) {
        break;
      }
      queue.push(prefix + opt.trim() + suffix);
    }
  }

  return results.length > 0 ? results : [pattern];
}

function matchCharClass(pattern: string, pIdx: number, ch: string): { matched: boolean; nextIdx: number } {
  let i = pIdx + 1;
  if (i >= pattern.length) {
    return { matched: ch === '[', nextIdx: pIdx + 1 };
  }
  let negate = false;
  if (pattern[i] === '!' || pattern[i] === '^') {
    negate = true;
    i += 1;
  }
  let found = false;
  const startContent = i;
  while (i < pattern.length) {
    if (pattern[i] === ']' && i > startContent) {
      return { matched: negate ? !found : found, nextIdx: i + 1 };
    }
    if (i + 2 < pattern.length && pattern[i + 1] === '-' && pattern[i + 2] !== ']') {
      const lo = pattern.charCodeAt(i);
      const hi = pattern.charCodeAt(i + 2);
      const code = ch.charCodeAt(0);
      if (code >= lo && code <= hi) {
        found = true;
      }
      i += 3;
    } else {
      if (pattern[i] === ch) {
        found = true;
      }
      i += 1;
    }
  }
  return { matched: ch === '[', nextIdx: pIdx + 1 };
}

/**
 * Matches a single path segment (no `/`) against a glob segment (supporting `*`, `?`, `[...]`).
 */
function matchSingleSegment(segPattern: string, segValue: string): boolean {
  let p = 0;
  let s = 0;
  let starP = -1;
  let starS = 0;

  while (s < segValue.length) {
    if (p < segPattern.length && segPattern[p] === '*') {
      starP = p;
      starS = s;
      p += 1;
    } else if (p < segPattern.length && segPattern[p] === '?') {
      p += 1;
      s += 1;
    } else if (p < segPattern.length && segPattern[p] === '[') {
      const cls = matchCharClass(segPattern, p, segValue[s]!);
      if (cls.matched) {
        p = cls.nextIdx;
        s += 1;
      } else if (starP !== -1) {
        p = starP + 1;
        starS += 1;
        s = starS;
      } else {
        return false;
      }
    } else if (p < segPattern.length && segPattern[p] === segValue[s]) {
      p += 1;
      s += 1;
    } else if (starP !== -1) {
      p = starP + 1;
      starS += 1;
      s = starS;
    } else {
      return false;
    }
  }

  while (p < segPattern.length && segPattern[p] === '*') {
    p += 1;
  }

  return p === segPattern.length;
}

function matchNormalizedSegments(patSegs: readonly string[], pathSegs: readonly string[]): boolean {
  const m = patSegs.length;
  const n = pathSegs.length;

  // dp[i][j] = patSegs[0..i-1] matches pathSegs[0..j-1]
  let prev = new Uint8Array(n + 1);
  prev[0] = 1;

  for (let i = 1; i <= m; i += 1) {
    const curr = new Uint8Array(n + 1);
    const pat = patSegs[i - 1]!;
    if (pat === '**') {
      curr[0] = prev[0]!;
      for (let j = 1; j <= n; j += 1) {
        curr[j] = prev[j]! || curr[j - 1]! ? 1 : 0;
      }
    } else {
      for (let j = 1; j <= n; j += 1) {
        if (prev[j - 1] && matchSingleSegment(pat, pathSegs[j - 1]!)) {
          curr[j] = 1;
        }
      }
    }
    prev = curr;
  }

  return prev[n] === 1;
}

export function splitGlobList(raw: unknown): string[] {
  if (typeof raw === 'string') {
    // Split top-level commas not inside `{...}`
    const out: string[] = [];
    let depth = 0;
    let start = 0;
    for (let i = 0; i < raw.length; i += 1) {
      const ch = raw[i];
      if (ch === '{') depth += 1;
      else if (ch === '}' && depth > 0) depth -= 1;
      else if (ch === ',' && depth === 0) {
        const piece = raw.slice(start, i).trim();
        if (piece.length > 0) out.push(piece);
        start = i + 1;
      }
    }
    const tail = raw.slice(start).trim();
    if (tail.length > 0) out.push(tail);
    return out;
  }
  if (Array.isArray(raw)) {
    const out: string[] = [];
    for (const item of raw) {
      if (typeof item === 'string' && item.trim().length > 0) {
        out.push(...splitGlobList(item));
      }
    }
    return out;
  }
  return [];
}

export function isUniversalGlob(patterns: readonly string[]): boolean {
  for (const raw of patterns) {
    const norm = normalizePosix(raw);
    if (norm === '**' || norm === '**/*' || norm === '*') {
      return true;
    }
  }
  return false;
}

export function matchGlob(rawPattern: string, relFilePosix: string): boolean {
  const cleanFile = normalizePosix(relFilePosix);
  if (cleanFile.length === 0) return false;
  const pathSegs = cleanFile.split('/');

  let basePattern = rawPattern.trim();
  if (basePattern.startsWith('!')) {
    return false;
  }
  basePattern = normalizePosix(basePattern);
  if (basePattern.length === 0) return false;

  const expanded = expandBraces(basePattern);
  for (const pat of expanded) {
    const normPat = normalizePosix(pat);
    // In Cursor/Copilot globs, a bare filename pattern without slashes (like `*.ts`) matches at any depth too
    const patSegs = normPat.includes('/') ? normPat.split('/') : ['**', normPat];
    if (matchNormalizedSegments(patSegs, pathSegs)) {
      return true;
    }
    if (!normPat.includes('/') && matchNormalizedSegments([normPat], pathSegs)) {
      return true;
    }
  }
  return false;
}

export function anyFileMatchesGlobs(patterns: readonly string[], repoFilesPosix: readonly string[]): boolean {
  if (patterns.length === 0) return false;
  const positive = patterns.filter((p) => !p.trim().startsWith('!'));
  const negative = patterns
    .filter((p) => p.trim().startsWith('!'))
    .map((p) => p.trim().slice(1).trim())
    .filter((p) => p.length > 0);

  if (positive.length === 0) return false;

  for (const file of repoFilesPosix) {
    const matchedPos = positive.some((pat) => matchGlob(pat, file));
    if (!matchedPos) continue;
    const matchedNeg = negative.some((pat) => matchGlob(pat, file));
    if (!matchedNeg) {
      return true;
    }
  }
  return false;
}
