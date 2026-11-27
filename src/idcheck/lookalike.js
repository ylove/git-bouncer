// Look-alike names: is this owner or repo name trying to pass for a well-known one?
//
// Impersonators use three tricks, so there are three defenses:
//
//  1. Characters that look the same: "micr0s0ft" (zero for o), "rnicrosoft" (r+n for m), "face-book".
//     Plain edit distance underrates these. "micr0s0ft" is 2 edits from "microsoft" but looks identical,
//     while "openaq" (a real, unrelated air-quality org) is only 1 edit from "openai". So before
//     comparing, both names are reduced to a "skeleton" in which characters that look alike become the
//     same character. This is the idea behind Unicode's confusable detection (UTS #39), cut down to the
//     ASCII tricks that work in GitHub names. Same skeleton, different name: a look-alike.
//
//  2. Typos: "vercell", "mircosoft". These are measured as edit distance between the skeletons.
//
//  3. The brand plus a company-sounding word, or minus one: "microsoft-official", "uniswap-labs", or
//     "mistral" when the real account is "mistralai". These are compared by their "stem", the name with
//     common prefixes and suffixes (official-, -labs, -ai, -dev, ...) taken off.
//
// And rules against false alarms, because a security tool that cries wolf teaches people to ignore it:
//  - A name that is itself on the known list is never a look-alike of another known name.
//  - How close counts depends on the length of the well-known name (see MATCH RULES below). In a short
//    name, one changed letter is usually a different word ("ample" isn't "apple"), not a disguise.
//  - A typo match must keep the first letter. People notice a wrong first letter, and dropping it
//    tends to produce unrelated real words ("llama" vs "ollama", "interest" vs "pinterest").
//  - A name made only of digits is a number, not a disguise ("8483" isn't "babe", a look-alike of babel).
// The ID check (index.js) also uses the GitHub API to soften a plain typo match on an old, established
// account. Disguised characters never get softened: nobody writes "micr0s0ft" by accident.

// Single characters that stand in for letters. "1", "i" and "l" are all a vertical stroke, so they
// collapse into one class.
const LOOKALIKE_CHARS = { 0: 'o', 1: 'l', i: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b' }
// Pairs of letters that read as one letter. Applied after the single characters, so "c1" -> "cl" -> "d".
const LOOKALIKE_PAIRS = [['rn', 'm'], ['vv', 'w'], ['cl', 'd']]
const HAS_PAIR = /rn|vv|cl/

/** Lowercase with separators removed: "Next.js" -> "nextjs". GitHub names ignore case. */
export function loose(name) {
  return String(name).toLowerCase().replace(/[-_.]/g, '')
}

/**
 * Reduce a name to its look-alike skeleton: "Micr0-s0ft" -> "mlcrosoft", "rnicrosoft" -> "mlcrosoft".
 * Only for comparing two names with each other. A skeleton isn't meant to be read or shown.
 */
export function skeleton(name) {
  let s = singleCharSkeleton(name)
  for (const [pair, letter] of LOOKALIKE_PAIRS) s = s.split(pair).join(letter)
  return s
}

// The skeleton without the letter pairs. Typos are measured on this form, because folding pairs distorts
// lengths: it can hide a typo ("vercl" is "vercel" missing an "e", but its "cl" folds to "d") and invent
// one ("golangci", a real org, folds to "golangd", one letter from "golang"). Only when the suspect
// itself is written with a pair ("rnicrosft") is the folded form measured too.
function singleCharSkeleton(name) {
  const l = loose(name)
  if (/^[0-9]+$/.test(l)) return l
  return l.replace(/[01i34578]/g, ch => LOOKALIKE_CHARS[ch])
}

// Words people wrap around a brand to make an account sound official. Longest first, so "labs" is
// tried before "lab".
const STEM_PREFIXES = ['official', 'real', 'the']
const STEM_SUFFIXES = ['official', 'project', 'labs', 'apps', 'team', 'lab', 'dev', 'inc', 'org', 'app', 'ai', 'hq', 'io', 'js', 'sh', 'rs', 'lm']
export const MIN_STEM_LENGTH = 5

/**
 * The name with brand-wrapping words taken off: "microsoft-official" -> "microsoft", "the-uniswap-labs"
 * -> "uniswap". Nothing is taken off if fewer than MIN_STEM_LENGTH letters would be left ("openai"
 * stays "openai", not "open").
 * @param {{glued?: boolean}} [opts]  glued: also take off words written without a separator
 *   ("mistralai" -> "mistral"). Used for the well-known names only. A suspect's glued words are left
 *   alone, because real, unrelated projects are named that way ("realpython", "jupyterlab",
 *   "postgresapp", "nginxinc" were all false alarms when glued words counted on both sides).
 */
export function stem(name, { glued = false } = {}) {
  let s = String(name).toLowerCase()
  for (let pass = 0; pass < 3; pass++) {
    let next = s
    for (const p of STEM_PREFIXES) {
      const rest = next.slice(p.length)
      if (next.startsWith(p) && (glued || /^[-_.]/.test(rest))) next = take(next, rest.replace(/^[-_.]/, ''))
    }
    for (const x of STEM_SUFFIXES) {
      const rest = next.slice(0, -x.length)
      if (next.endsWith(x) && (glued || /[-_.]$/.test(rest))) next = take(next, rest.replace(/[-_.]$/, ''))
    }
    if (next === s) break
    s = next
  }
  return loose(s)
}
const take = (before, after) => (loose(after).length >= MIN_STEM_LENGTH ? after : before)

/**
 * Damerau-Levenshtein distance, in the common "optimal string alignment" form: the number of
 * single-character insertions, deletions, substitutions and swaps of two neighbouring characters
 * needed to turn a into b. "vercel" -> "vercell" is 1 (insertion), "microsoft" -> "mircosoft" is 1 (swap).
 */
export function editDistance(a, b) {
  let prevPrev = null
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j)
  for (let i = 1; i <= a.length; i++) {
    const row = [i]
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1
      row[j] = Math.min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + cost)
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) row[j] = Math.min(row[j], prevPrev[j - 2] + 1)
    }
    prevPrev = prev
    prev = row
  }
  return prev[b.length]
}

/**
 * For two strings exactly one edit apart, what kind of edit was it, seen from the suspect name?
 * @returns {'extra'|'missing'|'swapped'|'changed'}
 */
function oneEditKind(suspect, known) {
  if (suspect.length === known.length + 1) return 'extra'
  if (suspect.length + 1 === known.length) return 'missing'
  let i = 0
  while (suspect[i] === known[i]) i++
  return suspect[i] === known[i + 1] && suspect[i + 1] === known[i] ? 'swapped' : 'changed'
}

// MATCH RULES. "Length" is the well-known name's length without separators.
//   1-3 letters   never compared: too many real names are one letter apart ("vue", "aws", "npm")
//   4             only look-alike characters count ("ub3r")
//   5-7           also one extra, missing or swapped letter ("vercell", "gogle", "goolge")
//   8-11          also one changed letter ("micrasoft")
//   12 and more   also two edits ("modelcontextptorocol"): in a long name, two slips are easy to miss
// Brand stems (rule 3) need at least MIN_STEM_LENGTH letters on both sides.
export const MIN_LENGTH = 4
const TYPO_LENGTH = 5
const CHANGED_LETTER_LENGTH = 8
const TWO_EDIT_LENGTH = 12

/** Kinds that mean the name was disguised on purpose: these are never softened. */
export const DISGUISE_KINDS = Object.freeze(['separators', 'characters'])
/** Kinds that could be an honest typo or a different real name. */
export const TYPO_KINDS = Object.freeze(['extra', 'missing', 'swapped', 'changed', 'two-edits'])

function typoMatch(suspect, known, k) {
  if (suspect[0] !== known[0]) return null
  const d = editDistance(suspect, known)
  if (d === 1) {
    const kind = oneEditKind(suspect, known)
    return kind !== 'changed' || k.loose.length >= CHANGED_LETTER_LENGTH ? { match: k.name, kind } : null
  }
  return d === 2 && k.loose.length >= TWO_EDIT_LENGTH ? { match: k.name, kind: 'two-edits' } : null
}

/**
 * Build a matcher for a list of well-known names. Skeletons and stems are computed once, up front.
 * @param {Iterable<string>} knownNames
 * @returns {(name: string) => null | {match: string, kind: string}}
 *   kind: how `name` differs from `match`, strongest first:
 *     separators  only in "-", "_", "." (face-book)
 *     characters  in look-alike characters, maybe separators too (micr0s0ft, rnicrosoft, m1crosoft-official)
 *     extra / missing / swapped / changed / two-edits   typo-style edits after look-alike characters
 *     stem        the same brand with a company-sounding word added or removed (microsoft-official, mistral)
 */
export function createMatcher(knownNames) {
  const known = [...knownNames].map(name => {
    const st = stem(name, { glued: true })
    return { name, lower: name.toLowerCase(), loose: loose(name), chars: singleCharSkeleton(name), skeleton: skeleton(name), stem: st, stemSkeleton: skeleton(st) }
  })
  const exact = new Set(known.map(k => k.lower))
  return function findLookalike(name) {
    if (typeof name !== 'string' || name.length === 0) return null
    if (exact.has(name.toLowerCase())) return null // it IS a known name, so it isn't pretending to be one
    const l = loose(name)
    const chars = singleCharSkeleton(name)
    const full = skeleton(name)
    const written = HAS_PAIR.test(l)
    const st = stem(name)
    const stSkeleton = skeleton(st)
    let typo = null
    let brand = null
    for (const k of known) {
      if (k.loose.length < MIN_LENGTH) continue
      if (full === k.skeleton) return { match: k.name, kind: l === k.loose ? 'separators' : 'characters' }
      if (!typo && k.loose.length >= TYPO_LENGTH) typo = typoMatch(chars, k.chars, k) ?? (written ? typoMatch(full, k.skeleton, k) : null)
      if (st.length >= MIN_STEM_LENGTH && k.stem.length >= MIN_STEM_LENGTH && stSkeleton === k.stemSkeleton) {
        if (st !== k.stem) return { match: k.name, kind: 'characters' } // a disguised brand plus a word
        brand ??= { match: k.name, kind: 'stem' }
      }
    }
    return typo ?? brand
  }
}
