import YAML, { isAlias, isMap, isPair, isScalar, isSeq } from 'yaml';
import {
  createNullRecord,
  type FrontmatterParseResult,
  MAX_YAML_ALIAS_COUNT,
} from './types.js';

const DANGEROUS_YAML_KEYS: ReadonlySet<string> = new Set([
  '__proto__',
  'constructor',
  'prototype',
]);

const RECOGNIZED_IMPORT_EXTENSIONS: ReadonlySet<string> = new Set([
  '.md',
  '.mdc',
  '.markdown',
  '.txt',
  '.json',
  '.yaml',
  '.yml',
  '.toml',
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.py',
  '.sh',
  '.ps1',
  '.go',
  '.rs',
  '.sql',
  '.css',
  '.html',
  '.xml',
  '.csv',
  '.cfg',
  '.ini',
  '.conf',
  '.rules',
]);

export interface InlineCodeSpan {
  code: string;
  line: number;
  column: number;
}

export interface FencedCodeBlock {
  lang: string;
  startLine: number;
  endLine: number;
  lines: Array<{ line: number; text: string }>;
}

export interface MarkdownLinkRef {
  label: string;
  target: string;
  isImage: boolean;
  line: number;
  column: number;
  endColumn: number;
}

export interface HtmlCommentSpan {
  raw: string;
  line: number;
  column: number;
}

export interface ClaudeImportRef {
  rawToken: string;
  targetPath: string;
  line: number;
  column: number;
}

export interface ProseLine {
  line: number;
  rawText: string;
  /** Same length as `rawText` with inline code spans masked by spaces so columns remain exact. */
  maskedText: string;
  inlineSpans: InlineCodeSpan[];
}

export interface ParsedMarkdown {
  hasBom: boolean;
  cleanContent: string;
  lines: string[];
  frontmatter: FrontmatterParseResult;
  fencedBlocks: FencedCodeBlock[];
  proseLines: ProseLine[];
  links: MarkdownLinkRef[];
  htmlComments: HtmlCommentSpan[];
  claudeImports: ClaudeImportRef[];
}

export function stripLeadingBom(raw: string): { content: string; hasBom: boolean } {
  if (raw.length > 0 && raw.charCodeAt(0) === 0xfeff) {
    return { content: raw.slice(1), hasBom: true };
  }
  return { content: raw, hasBom: false };
}

export function splitLinesPreserveCount(content: string): string[] {
  const out: string[] = [];
  let start = 0;
  for (let i = 0; i < content.length; i += 1) {
    if (content.charCodeAt(i) === 0x0a) {
      const end = i > start && content.charCodeAt(i - 1) === 0x0d ? i - 1 : i;
      out.push(content.slice(start, end));
      start = i + 1;
    }
  }
  out.push(content.slice(start));
  return out;
}

interface YamlAstWalkState {
  dangerousKeys: Set<string>;
  aliasCount: number;
  aliasLimitExceeded: boolean;
}

function materializeSafeYamlNode(
  node: unknown,
  doc: YAML.Document,
  state: YamlAstWalkState,
  depth = 0,
): unknown {
  if (depth > 32 || node === null || node === undefined) {
    return null;
  }
  if (isScalar(node)) {
    return node.value;
  }
  if (isAlias(node)) {
    state.aliasCount += 1;
    if (state.aliasCount > MAX_YAML_ALIAS_COUNT) {
      state.aliasLimitExceeded = true;
      return null;
    }
    const resolved = node.resolve(doc);
    return materializeSafeYamlNode(resolved, doc, state, depth + 1);
  }
  if (isSeq(node)) {
    const arr: unknown[] = [];
    for (const item of node.items) {
      arr.push(materializeSafeYamlNode(item, doc, state, depth + 1));
      if (state.aliasLimitExceeded) break;
    }
    return arr;
  }
  if (isMap(node)) {
    const obj = createNullRecord<unknown>();
    for (const pair of node.items) {
      if (!isPair(pair)) continue;
      let keyStr = '';
      if (isScalar(pair.key)) {
        keyStr = String(pair.key.value ?? '');
      } else if (pair.key !== null && pair.key !== undefined) {
        keyStr = String(pair.key);
      }
      if (DANGEROUS_YAML_KEYS.has(keyStr)) {
        state.dangerousKeys.add(keyStr);
        // Never assign dangerous key onto any object
        materializeSafeYamlNode(pair.value, doc, state, depth + 1);
        continue;
      }
      obj[keyStr] = materializeSafeYamlNode(pair.value, doc, state, depth + 1);
      if (state.aliasLimitExceeded) break;
    }
    return obj;
  }
  return null;
}

export function parseFrontmatterFromLines(lines: readonly string[]): FrontmatterParseResult {
  const emptyResult: FrontmatterParseResult = {
    present: false,
    empty: false,
    rawYaml: '',
    startLine: 1,
    endLine: 0,
    bodyStartLine: 1,
    data: createNullRecord<unknown>(),
    aliasLimitExceeded: false,
    dangerousKeys: [],
  };

  if (lines.length === 0) {
    return emptyResult;
  }

  if (lines[0]!.trimEnd() !== '---') {
    return emptyResult;
  }

  let closeIdx = -1;
  for (let i = 1; i < lines.length; i += 1) {
    const trimmed = lines[i]!.trimEnd();
    if (trimmed === '---' || trimmed === '...') {
      closeIdx = i;
      break;
    }
  }

  if (closeIdx === -1) {
    return emptyResult;
  }

  const yamlLines = lines.slice(1, closeIdx);
  const rawYaml = yamlLines.join('\n');
  const trimmedYaml = rawYaml.trim();

  if (trimmedYaml.length === 0) {
    return {
      present: true,
      empty: true,
      rawYaml,
      startLine: 1,
      endLine: closeIdx + 1,
      bodyStartLine: closeIdx + 2,
      data: createNullRecord<unknown>(),
      aliasLimitExceeded: false,
      dangerousKeys: [],
    };
  }

  const doc = YAML.parseDocument(rawYaml, {
    prettyErrors: false,
  });

  const walkState: YamlAstWalkState = {
    dangerousKeys: new Set<string>(),
    aliasCount: 0,
    aliasLimitExceeded: false,
  };

  let yamlError: string | undefined;
  if (doc.errors.length > 0) {
    const firstErr = doc.errors[0]!;
    yamlError = firstErr.message;
  } else {
    try {
      doc.toJS({ maxAliasCount: MAX_YAML_ALIAS_COUNT, mapAsMap: true });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      yamlError = msg;
      if (msg.toLowerCase().includes('alias')) {
        walkState.aliasLimitExceeded = true;
      }
    }
  }

  const materialized = materializeSafeYamlNode(doc.contents, doc, walkState);
  if (walkState.aliasLimitExceeded && !yamlError) {
    yamlError = `YAML alias expansion exceeded maximum limit (${MAX_YAML_ALIAS_COUNT})`;
  }

  const data =
    materialized !== null && typeof materialized === 'object' && !Array.isArray(materialized)
      ? (materialized as Record<string, unknown>)
      : createNullRecord<unknown>();

  const nonObjectFrontmatter =
    !yamlError &&
    doc.contents !== null &&
    (typeof materialized !== 'object' || materialized === null || Array.isArray(materialized));

  return {
    present: true,
    empty: Object.keys(data).length === 0 && walkState.dangerousKeys.size === 0 && !yamlError && !nonObjectFrontmatter,
    rawYaml,
    startLine: 1,
    endLine: closeIdx + 1,
    bodyStartLine: closeIdx + 2,
    data,
    ...(yamlError
      ? { yamlError }
      : nonObjectFrontmatter
        ? { yamlError: 'Frontmatter root must be a YAML mapping' }
        : {}),
    aliasLimitExceeded: walkState.aliasLimitExceeded,
    dangerousKeys: [...walkState.dangerousKeys],
  };
}

function parseFenceOpening(line: string): { fenceChar: '`' | '~'; fenceLen: number; lang: string } | null {
  let indent = 0;
  while (indent < line.length && indent < 4 && line[indent] === ' ') {
    indent += 1;
  }
  if (indent >= 4 || indent >= line.length) return null;
  const ch = line[indent];
  if (ch !== '`' && ch !== '~') return null;

  let len = 0;
  let i = indent;
  while (i < line.length && line[i] === ch) {
    len += 1;
    i += 1;
  }
  if (len < 3) return null;

  const info = line.slice(i).trim();
  // CommonMark rule: backtick fence info string cannot contain backticks
  if (ch === '`' && info.includes('`')) {
    return null;
  }
  const langToken = info.split(/\s+/)[0]?.toLowerCase() ?? '';
  return { fenceChar: ch, fenceLen: len, lang: langToken };
}

function isFenceClosing(line: string, fenceChar: '`' | '~', minLen: number): boolean {
  let indent = 0;
  while (indent < line.length && indent < 4 && line[indent] === ' ') {
    indent += 1;
  }
  if (indent >= 4 || indent >= line.length) return false;
  if (line[indent] !== fenceChar) return false;

  let len = 0;
  let i = indent;
  while (i < line.length && line[i] === fenceChar) {
    len += 1;
    i += 1;
  }
  if (len < minLen) return false;

  while (i < line.length) {
    const c = line[i];
    if (c !== ' ' && c !== '\t') return false;
    i += 1;
  }
  return true;
}

function extractInlineCodeAndMask(lineText: string, lineNo: number): {
  maskedText: string;
  inlineSpans: InlineCodeSpan[];
} {
  const spans: InlineCodeSpan[] = [];
  const chars = lineText.split('');
  let i = 0;

  while (i < lineText.length) {
    if (lineText[i] !== '`') {
      i += 1;
      continue;
    }
    if (i > 0 && lineText[i - 1] === '\\') {
      i += 1;
      continue;
    }
    let tickLen = 0;
    const startIdx = i;
    while (i < lineText.length && lineText[i] === '`') {
      tickLen += 1;
      i += 1;
    }

    // Find matching run of exact `tickLen` backticks
    let closeStart = -1;
    let scan = i;
    while (scan < lineText.length) {
      if (lineText[scan] !== '`') {
        scan += 1;
        continue;
      }
      const runStart = scan;
      let runLen = 0;
      while (scan < lineText.length && lineText[scan] === '`') {
        runLen += 1;
        scan += 1;
      }
      if (runLen === tickLen) {
        closeStart = runStart;
        break;
      }
    }

    if (closeStart !== -1) {
      const inner = lineText.slice(i, closeStart);
      spans.push({
        code: inner,
        line: lineNo,
        column: startIdx + 1,
      });
      const closeEnd = closeStart + tickLen;
      for (let m = startIdx; m < closeEnd; m += 1) {
        chars[m] = ' ';
      }
      i = closeEnd;
    }
  }

  return { maskedText: chars.join(''), inlineSpans: spans };
}

function extractLinksFromMaskedLine(maskedLine: string, lineNo: number): MarkdownLinkRef[] {
  const links: MarkdownLinkRef[] = [];
  let i = 0;
  while (i < maskedLine.length) {
    const openBracket = maskedLine.indexOf('[', i);
    if (openBracket === -1) break;
    if (openBracket > 0 && maskedLine[openBracket - 1] === '\\') {
      i = openBracket + 1;
      continue;
    }

    const isImage = openBracket > 0 && maskedLine[openBracket - 1] === '!';
    const startCol = isImage ? openBracket : openBracket + 1;

    // Find matching `]`
    let bracketDepth = 1;
    let j = openBracket + 1;
    while (j < maskedLine.length && bracketDepth > 0) {
      if (maskedLine[j] === '\\') {
        j += 2;
        continue;
      }
      if (maskedLine[j] === '[') bracketDepth += 1;
      else if (maskedLine[j] === ']') bracketDepth -= 1;
      j += 1;
    }

    if (bracketDepth !== 0) {
      i = openBracket + 1;
      continue;
    }

    const closeBracket = j - 1;
    if (closeBracket + 1 >= maskedLine.length || maskedLine[closeBracket + 1] !== '(') {
      i = closeBracket + 1;
      continue;
    }

    // Find matching `)` with 1-level balanced parens support
    let parenDepth = 1;
    let k = closeBracket + 2;
    while (k < maskedLine.length && parenDepth > 0) {
      if (maskedLine[k] === '\\') {
        k += 2;
        continue;
      }
      if (maskedLine[k] === '(') parenDepth += 1;
      else if (maskedLine[k] === ')') parenDepth -= 1;
      k += 1;
    }

    if (parenDepth !== 0) {
      i = closeBracket + 2;
      continue;
    }

    const closeParen = k - 1;
    const label = maskedLine.slice(openBracket + 1, closeBracket);
    const target = maskedLine.slice(closeBracket + 2, closeParen).trim();
    if (target.length > 0) {
      links.push({
        label,
        target,
        isImage,
        line: lineNo,
        column: startCol,
        endColumn: closeParen + 1,
      });
    }
    i = closeParen + 1;
  }
  return links;
}

function isLikelyClaudeImportTarget(targetPath: string): boolean {
  if (targetPath.length === 0 || targetPath.includes('://')) {
    return false;
  }
  // Explicit path prefixes always qualify as @path imports
  if (
    targetPath.startsWith('./') ||
    targetPath.startsWith('../') ||
    targetPath.startsWith('.\\') ||
    targetPath.startsWith('..\\') ||
    targetPath.startsWith('/') ||
    targetPath.startsWith('~/') ||
    targetPath.startsWith('~\\') ||
    /^[A-Za-z]:[/\\]/.test(targetPath)
  ) {
    return true;
  }

  // Otherwise require a recognized file extension so `@scope/pkg` and `@mention` are never mistaken for @imports
  const normalized = targetPath.replace(/\\/g, '/');
  const base = normalized.slice(normalized.lastIndexOf('/') + 1);
  const dotIdx = base.lastIndexOf('.');
  if (dotIdx <= 0) {
    return false;
  }
  const ext = base.slice(dotIdx).toLowerCase();
  return RECOGNIZED_IMPORT_EXTENSIONS.has(ext);
}

function extractClaudeImportsFromMaskedLine(maskedLine: string, lineNo: number): ClaudeImportRef[] {
  const out: ClaudeImportRef[] = [];
  let i = 0;
  while (i < maskedLine.length) {
    const atIdx = maskedLine.indexOf('@', i);
    if (atIdx === -1) break;

    // Must be preceded by start-of-line or whitespace (excludes emails like user@example.com and links)
    if (atIdx > 0) {
      const prev = maskedLine[atIdx - 1]!;
      if (prev !== ' ' && prev !== '\t' && prev !== '(' && prev !== '[') {
        i = atIdx + 1;
        continue;
      }
    }

    let end = atIdx + 1;
    while (end < maskedLine.length) {
      const ch = maskedLine[end]!;
      if (ch === ' ' || ch === '\t' || ch === ')' || ch === ']' || ch === '>' || ch === '"' || ch === "'") {
        break;
      }
      end += 1;
    }

    let rawBody = maskedLine.slice(atIdx + 1, end);
    // Strip trailing sentence punctuation `,.;:!?`
    while (rawBody.length > 0 && ',.;:!?'.includes(rawBody[rawBody.length - 1]!)) {
      rawBody = rawBody.slice(0, -1);
    }

    if (isLikelyClaudeImportTarget(rawBody)) {
      out.push({
        rawToken: `@${rawBody}`,
        targetPath: rawBody,
        line: lineNo,
        column: atIdx + 1,
      });
    }

    i = Math.max(atIdx + 1, end);
  }
  return out;
}

function extractHtmlCommentsOutsideFences(proseLines: readonly ProseLine[]): HtmlCommentSpan[] {
  if (proseLines.length === 0) return [];
  const out: HtmlCommentSpan[] = [];

  let inComment = false;
  let commentStartLine = 1;
  let commentStartCol = 1;
  let buffer = '';

  for (const pl of proseLines) {
    const text = pl.maskedText;
    let pos = 0;
    while (pos < text.length) {
      if (!inComment) {
        const openIdx = text.indexOf('<!--', pos);
        if (openIdx === -1) break;
        const closeIdx = text.indexOf('-->', openIdx + 4);
        if (closeIdx !== -1) {
          out.push({
            raw: pl.rawText.slice(openIdx, closeIdx + 3),
            line: pl.line,
            column: openIdx + 1,
          });
          pos = closeIdx + 3;
        } else {
          inComment = true;
          commentStartLine = pl.line;
          commentStartCol = openIdx + 1;
          buffer = pl.rawText.slice(openIdx);
          break;
        }
      } else {
        const closeIdx = text.indexOf('-->', pos);
        if (closeIdx !== -1) {
          buffer += `\n${pl.rawText.slice(0, closeIdx + 3)}`;
          out.push({
            raw: buffer,
            line: commentStartLine,
            column: commentStartCol,
          });
          inComment = false;
          buffer = '';
          pos = closeIdx + 3;
        } else {
          buffer += `\n${pl.rawText}`;
          break;
        }
      }
    }
  }

  if (inComment) {
    out.push({
      raw: buffer,
      line: commentStartLine,
      column: commentStartCol,
    });
  }

  return out;
}

export function parseMarkdownDocument(rawContent: string): ParsedMarkdown {
  const { content: cleanContent, hasBom } = stripLeadingBom(rawContent);
  const lines = splitLinesPreserveCount(cleanContent);
  const frontmatter = parseFrontmatterFromLines(lines);

  const fencedBlocks: FencedCodeBlock[] = [];
  const proseLines: ProseLine[] = [];
  const links: MarkdownLinkRef[] = [];
  const claudeImports: ClaudeImportRef[] = [];

  let activeFence: {
    fenceChar: '`' | '~';
    fenceLen: number;
    lang: string;
    startLine: number;
    lines: Array<{ line: number; text: string }>;
  } | null = null;

  const startIdx = Math.max(0, frontmatter.bodyStartLine - 1);
  for (let idx = startIdx; idx < lines.length; idx += 1) {
    const lineNo = idx + 1;
    const rawLine = lines[idx]!;

    if (!activeFence) {
      const open = parseFenceOpening(rawLine);
      if (open) {
        activeFence = {
          fenceChar: open.fenceChar,
          fenceLen: open.fenceLen,
          lang: open.lang,
          startLine: lineNo,
          lines: [],
        };
        continue;
      }

      const { maskedText, inlineSpans } = extractInlineCodeAndMask(rawLine, lineNo);
      proseLines.push({
        line: lineNo,
        rawText: rawLine,
        maskedText,
        inlineSpans,
      });
      links.push(...extractLinksFromMaskedLine(maskedText, lineNo));
      claudeImports.push(...extractClaudeImportsFromMaskedLine(maskedText, lineNo));
    } else {
      if (isFenceClosing(rawLine, activeFence.fenceChar, activeFence.fenceLen)) {
        fencedBlocks.push({
          lang: activeFence.lang,
          startLine: activeFence.startLine,
          endLine: lineNo,
          lines: activeFence.lines,
        });
        activeFence = null;
      } else {
        activeFence.lines.push({ line: lineNo, text: rawLine });
      }
    }
  }

  if (activeFence) {
    fencedBlocks.push({
      lang: activeFence.lang,
      startLine: activeFence.startLine,
      endLine: lines.length,
      lines: activeFence.lines,
    });
  }

  const htmlComments = extractHtmlCommentsOutsideFences(proseLines);

  return {
    hasBom,
    cleanContent,
    lines,
    frontmatter,
    fencedBlocks,
    proseLines,
    links,
    htmlComments,
    claudeImports,
  };
}
