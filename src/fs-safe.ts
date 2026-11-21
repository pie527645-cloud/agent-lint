import fs from 'node:fs';
import path from 'node:path';
import { DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_SCANNED_FILES } from './types.js';

export interface DirListingCacheEntry {
  exact: Map<string, fs.Dirent>;
  lower: Map<string, string[]>;
}

export type PathCheckResult =
  | {
      status: 'ok';
      resolvedAbs: string;
      realPath: string;
      isDirectory: boolean;
    }
  | {
      status: 'case-mismatch';
      resolvedAbs: string;
      expectedSegment: string;
      actualSegment: string;
    }
  | {
      status: 'missing';
      resolvedAbs: string;
    }
  | {
      status: 'escaped-root';
      resolvedAbs: string;
    };

export const IGNORED_WALK_DIRS: ReadonlySet<string> = new Set([
  '.git',
  'node_modules',
  'dist',
  'dist-test',
  'dist-tests',
  'build',
  'out',
  'coverage',
  '.next',
  '.nuxt',
  '.turbo',
  '.cache',
  'target',
  'vendor',
  '.venv',
  'venv',
  '__pycache__',
]);

export const AGENT_DOT_DIRS: ReadonlySet<string> = new Set([
  '.github',
  '.claude',
  '.gemini',
  '.cursor',
  '.agents',
]);

export function toPosixPath(p: string): string {
  return p.split(path.sep).join('/').replace(/\\/g, '/');
}

export function isRealpathInsideRoot(targetPath: string, rootReal: string): boolean {
  const rel = path.relative(rootReal, targetPath);
  if (rel === '') return true;
  if (rel === '..' || rel.startsWith(`..${path.sep}`) || rel.startsWith('../')) {
    return false;
  }
  if (path.isAbsolute(rel)) {
    return false;
  }
  return true;
}

/**
 * Strips `#anchor`, `?query`, surrounding `<...>`, and trailing `:line(:col)` suffixes
 * while preserving Windows drive letters if present (so lexical escape detection catches them).
 */
export function normalizePathReference(raw: string): string {
  let s = raw.trim();
  if (s.startsWith('<') && s.endsWith('>') && s.length > 2) {
    s = s.slice(1, -1).trim();
  }
  // Strip markdown link title if present: `path/to/file.md "Title"`
  const spaceQuoteIdx = s.search(/\s+['"]/);
  if (spaceQuoteIdx > 0) {
    s = s.slice(0, spaceQuoteIdx).trim();
  }
  const hashIdx = s.indexOf('#');
  if (hashIdx !== -1) {
    s = s.slice(0, hashIdx);
  }
  const queryIdx = s.indexOf('?');
  if (queryIdx !== -1) {
    s = s.slice(0, queryIdx);
  }
  // Convert Windows backslashes to forward slashes
  s = s.replace(/\\/g, '/');

  // Strip trailing `:line` or `:line:col` (avoiding `C:` drive prefix at index 1)
  const lastColon = s.lastIndexOf(':');
  if (lastColon > 1) {
    const tail = s.slice(lastColon + 1);
    if (/^\d+$/.test(tail)) {
      s = s.slice(0, lastColon);
      const prevColon = s.lastIndexOf(':');
      if (prevColon > 1 && /^\d+$/.test(s.slice(prevColon + 1))) {
        s = s.slice(0, prevColon);
      }
    }
  }
  return s.trim();
}

export class SafeFsContext {
  public readonly rootDirReal: string;
  public readonly maxFileBytes: number;
  public readonly maxScannedFiles: number;
  private readonly dirCache = new Map<string, DirListingCacheEntry | null>();

  constructor(
    rootDir: string,
    options?: { maxFileBytes?: number; maxScannedFiles?: number },
  ) {
    this.rootDirReal = fs.realpathSync(rootDir);
    this.maxFileBytes = options?.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    this.maxScannedFiles = options?.maxScannedFiles ?? DEFAULT_MAX_SCANNED_FILES;
  }

  public getDirEntries(dirAbs: string): DirListingCacheEntry | null {
    const key = path.resolve(dirAbs);
    if (this.dirCache.has(key)) {
      return this.dirCache.get(key) ?? null;
    }
    try {
      const entries = fs.readdirSync(key, { withFileTypes: true });
      // Sort deterministically by UTF-16 code units
      entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      const exact = new Map<string, fs.Dirent>();
      const lower = new Map<string, string[]>();
      for (const d of entries) {
        exact.set(d.name, d);
        const lc = d.name.toLowerCase();
        const list = lower.get(lc);
        if (list) {
          list.push(d.name);
        } else {
          lower.set(lc, [d.name]);
        }
      }
      const record: DirListingCacheEntry = { exact, lower };
      this.dirCache.set(key, record);
      return record;
    } catch {
      this.dirCache.set(key, null);
      return null;
    }
  }

  /**
   * Verifies a path reference relative to `fromDirAbs` with strict `realpathSync` containment
   * and case-exact directory entry verification on all platforms (including Windows and macOS).
   */
  public checkCaseExactPath(fromDirAbs: string, rawReference: string): PathCheckResult {
    const cleaned = normalizePathReference(rawReference);
    if (cleaned.length === 0) {
      return { status: 'missing', resolvedAbs: fromDirAbs };
    }

    // Explicit tilde home expansion (`~/...` or `~\...`) is always outside repo root
    if (cleaned === '~' || cleaned.startsWith('~/')) {
      return { status: 'escaped-root', resolvedAbs: cleaned };
    }

    // Leading `/` on Windows `path.resolve('C:\\repo', '/etc/passwd')` resolves to `C:\\etc\\passwd`
    // which is also outside `C:\\repo`.
    const candidateAbs = path.resolve(fromDirAbs, cleaned);
    if (!isRealpathInsideRoot(candidateAbs, this.rootDirReal)) {
      return { status: 'escaped-root', resolvedAbs: candidateAbs };
    }

    const rel = path.relative(this.rootDirReal, candidateAbs);
    if (rel === '') {
      return {
        status: 'ok',
        resolvedAbs: this.rootDirReal,
        realPath: this.rootDirReal,
        isDirectory: true,
      };
    }

    const segments = rel.split(path.sep).filter((seg) => seg.length > 0);
    let currentAbs = this.rootDirReal;

    for (let i = 0; i < segments.length; i += 1) {
      const seg = segments[i]!;
      const listing = this.getDirEntries(currentAbs);
      if (!listing) {
        return { status: 'missing', resolvedAbs: candidateAbs };
      }

      const dirent = listing.exact.get(seg);
      if (!dirent) {
        const caseMatches = listing.lower.get(seg.toLowerCase());
        if (caseMatches && caseMatches.length > 0) {
          return {
            status: 'case-mismatch',
            resolvedAbs: candidateAbs,
            expectedSegment: seg,
            actualSegment: caseMatches[0]!,
          };
        }
        return { status: 'missing', resolvedAbs: candidateAbs };
      }

      const nextAbs = path.join(currentAbs, seg);
      let nextReal: string;
      try {
        nextReal = fs.realpathSync(nextAbs);
      } catch {
        // Broken symlink: check whether link target itself points outside root
        try {
          const rawLink = fs.readlinkSync(nextAbs);
          const linkResolved = path.resolve(currentAbs, rawLink);
          if (!isRealpathInsideRoot(linkResolved, this.rootDirReal)) {
            return { status: 'escaped-root', resolvedAbs: linkResolved };
          }
        } catch {
          // Not a readable symlink
        }
        return { status: 'missing', resolvedAbs: nextAbs };
      }

      if (!isRealpathInsideRoot(nextReal, this.rootDirReal)) {
        return { status: 'escaped-root', resolvedAbs: nextReal };
      }

      if (i === segments.length - 1) {
        let isDirectory = dirent.isDirectory();
        if (dirent.isSymbolicLink()) {
          try {
            isDirectory = fs.statSync(nextReal).isDirectory();
          } catch {
            isDirectory = false;
          }
        }
        return {
          status: 'ok',
          resolvedAbs: nextAbs,
          realPath: nextReal,
          isDirectory,
        };
      }

      currentAbs = nextAbs;
    }

    return { status: 'missing', resolvedAbs: candidateAbs };
  }

  /**
   * Collects repository relative POSIX file paths for glob validation and top-level directory inventory.
   */
  public collectRepoInventory(): {
    filesPosix: string[];
    topLevelDirs: Set<string>;
    escapedPaths: Array<{ relPath: string; targetPath: string }>;
    truncatedByCap: boolean;
  } {
    const filesPosix: string[] = [];
    const topLevelDirs = new Set<string>();
    const escapedPaths: Array<{ relPath: string; targetPath: string }> = [];
    let truncatedByCap = false;

    const stack: Array<{ absDir: string; relDirPosix: string }> = [
      { absDir: this.rootDirReal, relDirPosix: '' },
    ];

    while (stack.length > 0) {
      const current = stack.pop()!;
      const listing = this.getDirEntries(current.absDir);
      if (!listing) continue;

      const entries = [...listing.exact.values()];
      // Push directories in reverse order so `.pop()` visits in lexicographical order
      const subdirs: Array<{ absDir: string; relDirPosix: string }> = [];

      for (const entry of entries) {
        const name = entry.name;
        const relPosix = current.relDirPosix ? `${current.relDirPosix}/${name}` : name;
        const childAbs = path.join(current.absDir, name);

        if (entry.isDirectory() && IGNORED_WALK_DIRS.has(name)) {
          continue;
        }
        // Skip hidden dot-directories at any level unless they are recognized agent/CI dirs
        if (
          (entry.isDirectory() || entry.isSymbolicLink()) &&
          name.startsWith('.') &&
          !AGENT_DOT_DIRS.has(name) &&
          name !== '.vscode'
        ) {
          if (entry.isDirectory()) {
            continue;
          }
        }

        let childReal: string;
        let stat: fs.Stats;
        try {
          childReal = fs.realpathSync(childAbs);
          stat = fs.statSync(childReal);
        } catch {
          // Check broken symlink escaping root
          try {
            const linkTarget = path.resolve(current.absDir, fs.readlinkSync(childAbs));
            if (!isRealpathInsideRoot(linkTarget, this.rootDirReal)) {
              escapedPaths.push({ relPath: relPosix, targetPath: linkTarget });
            }
          } catch {
            // Ignore unreadable transient entry
          }
          continue;
        }

        if (!isRealpathInsideRoot(childReal, this.rootDirReal)) {
          escapedPaths.push({ relPath: relPosix, targetPath: childReal });
          continue;
        }

        if (stat.isDirectory()) {
          if (IGNORED_WALK_DIRS.has(name)) continue;
          if (current.relDirPosix === '') {
            topLevelDirs.add(name);
          }
          subdirs.push({ absDir: childAbs, relDirPosix: relPosix });
        } else if (stat.isFile()) {
          if (filesPosix.length >= this.maxScannedFiles) {
            truncatedByCap = true;
            break;
          }
          filesPosix.push(relPosix);
        }
      }

      if (truncatedByCap) {
        break;
      }

      for (let i = subdirs.length - 1; i >= 0; i -= 1) {
        stack.push(subdirs[i]!);
      }
    }

    return { filesPosix, topLevelDirs, escapedPaths, truncatedByCap };
  }
}
