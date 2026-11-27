# Security policy

git-bouncer is a security tool, so a vulnerability in it is a vulnerability in every developer's first line of defense. Thank you for looking.

## Reporting a vulnerability

**Please don't open a public issue.** Use GitHub's private vulnerability reporting: open the repo's **Security** tab, then **Report a vulnerability** ([direct link](https://github.com/ylove/git-bouncer/security/advisories/new)).

Include what you can:
- the version (`bouncer --version`) and your OS and container runtime;
- a minimal repository or input that reproduces it;
- what an attacker gains (for example: code runs on the host, a FAIL is shown as PASS, a secret reaches the sandbox).

**What to expect:**
- An acknowledgement within 3 days.
- An assessment within 7 days.
- A fix or mitigation plan for confirmed issues as soon as practical. The goal is under 14 days for high-severity issues.
- Credit in the advisory if you'd like it.

## What counts

Especially wanted:
- anything that lets code from a scanned repository run on the host, or escape or influence the sandbox;
- anything that makes a malicious repo pass, or makes the verdict shown differ from the verdict computed (terminal injection, report spoofing);
- secrets or host files reaching the sandbox;
- weaknesses in how git-bouncer itself is built, released or installed.

Not vulnerabilities, but welcome as regular issues:
- a malicious technique the scanner doesn't detect yet ("detection gap");
- a false positive on a legitimate repo.

See [THREAT_MODEL.md](THREAT_MODEL.md) for what's in and out of scope.

## Supported versions

Only the latest release gets security fixes.
