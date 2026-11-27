# Contributing to git-bouncer

Thanks for helping. This repo is built in public on purpose: issues come before code, every change lands through a pull request, and review happens in the open. Reading the closed PRs in order is a decent way to learn how a security tool gets built.

## Ground rules

- **Zero runtime dependencies.** Node's standard library only. If you believe a dependency is truly necessary, open an issue first.
- **Never build shell command strings.** Every subprocess uses `spawn(cmd, [args])`, and user-supplied values go after `--`.
- **Treat everything from a scanned repo as hostile.** That includes file names, file contents, package metadata and error messages. Don't print it without going through the sanitizer.
- **The scanned repo can never configure the scanner.** No ignore files, no settings read from the target.
- **Tests generate their fixtures at runtime.** Don't commit "malicious-looking" files; build them in a temp directory inside the test.

## Workflow

1. Open (or pick) an issue describing the problem and the approach.
2. Branch as `<issue-number>-<short-slug>`.
3. Make small commits, and push often.
4. Open a PR using the template (What / Why / How it was tested / What to learn from this), with `Closes #N`.
5. CI must be green. Address review comments with new commits; please don't force-push them away.

## Adding a detection

New checks are very welcome. Please include:
- a link to the public write-up of the technique;
- a test that generates a minimal fixture and asserts the finding;
- a test showing a legitimate project doesn't trigger it (false positives teach people to ignore the tool);
- an entry in `docs/checks.md` with the ID, severity and plain-language explanation.

Detection gaps can be regular issues. Ways to **bypass or attack git-bouncer itself** go through [private reporting](SECURITY.md).
