// Text cleaning and redaction. Every string and key in every answer passes
// through cleanValue: characters in the contract's remove ranges are dropped,
// tab, line breaks and the Unicode line and paragraph separators become a
// space, and then every configured secret is replaced. Cleaning runs before
// redaction, so a secret split by a hidden character is still caught.

import { contract, type Range } from "./contract.js";

const SPACE: Range[] = contract.implementation.text_cleaning.replace_with_space;
const REMOVE: Range[] = contract.implementation.text_cleaning.remove;
const LINE_SEPARATORS: Range[] = [[0x2028, 0x2029]];

function inRanges(cp: number, ranges: Range[]): boolean {
  for (const [low, high] of ranges) {
    if (cp >= low && cp <= high) return true;
  }
  return false;
}

/** The string with hidden characters removed and line breaks as spaces. */
export function cleanString(text: string): string {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (inRanges(cp, SPACE)) out += " ";
    else if (!inRanges(cp, REMOVE)) out += ch;
  }
  return out;
}

/** Whether seal_decision must refuse this string: it holds a character in
 *  the remove ranges, or a line or paragraph separator. Tab, line feed and
 *  carriage return are allowed. */
export function hasRefusedCharacter(text: string): boolean {
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (inRanges(cp, REMOVE) || inRanges(cp, LINE_SEPARATORS)) return true;
  }
  return false;
}

export class Redactor {
  private readonly secrets: string[];
  private readonly pattern: RegExp;
  private readonly replacement: string;

  constructor(secrets: Array<string | undefined>) {
    this.secrets = [...new Set(secrets.filter((s): s is string => typeof s === "string" && s.length >= 8))].sort(
      (a, b) => b.length - a.length,
    );
    this.pattern = new RegExp(contract.implementation.redaction.pattern, "g");
    this.replacement = contract.implementation.redaction.replacement;
  }

  redact(text: string): string {
    let out = text;
    for (const secret of this.secrets) out = out.split(secret).join(this.replacement);
    return out.replace(this.pattern, this.replacement);
  }

  /** Cleaning, then redaction, of one string. */
  text(value: string): string {
    return this.redact(cleanString(value));
  }

  /** A copy of a JSON value with every string and key cleaned and redacted. */
  value(input: unknown): unknown {
    if (typeof input === "string") return this.text(input);
    if (Array.isArray(input)) return input.map((v) => this.value(v));
    if (input !== null && typeof input === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(input as Record<string, unknown>)) out[this.text(k)] = this.value(v);
      return out;
    }
    return input;
  }
}
