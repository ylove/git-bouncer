// Path names the way macOS and Windows compare them.
//
// The sandbox runs on Linux, where `.vscode`, `.VSCode` and `.v<U+017F>code` (U+017F is a "long s";
// it uppercases to S) are three different folders. On APFS (macOS) and NTFS (Windows) they are one: both
// are case-insensitive by default, and APFS also ignores Unicode normalization (an "e" plus a combining
// accent is the same name as the precomposed letter). Old HFS+ also ignored some invisible code points.
// So every comparison between a repo path and a name some tool opens automatically goes through
// foldPath, and when several spellings fold together, every one of them is checked.

const IGNORABLE = /\p{Default_Ignorable_Code_Point}/gu

/**
 * Fold a path (or one name) so that any two spellings a case-insensitive, normalization-insensitive
 * filesystem would treat as the same file compare equal. Deliberately broader than any one filesystem:
 * merging two names that some filesystem keeps apart only makes the checks stricter.
 * Uppercasing before lowercasing is what maps U+017F to "s" and the Kelvin sign to "k".
 */
export function foldPath(s) {
  return String(s).normalize('NFD').toUpperCase().toLowerCase().normalize('NFD').replace(IGNORABLE, '')
}

/** Every entry in `names` that folds to the same name as `want` (all spellings, not just the first). */
export function variantsOf(names, want) {
  const w = foldPath(want)
  return names.filter(n => foldPath(n) === w)
}
