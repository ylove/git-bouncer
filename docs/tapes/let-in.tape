# Regenerate: from a checkout of the repo, run   BOUNCER_REPO="$PWD" vhs docs/tapes/let-in.tape
Output site/img/let-in.gif
Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 720
Set Padding 24
Set TypingSpeed 45ms
Set Theme "GitHub Dark"

Hide
Type `alias bouncer='node "$BOUNCER_REPO/bin/bouncer.js"'; cd "$(mktemp -d)"; clear`
Enter
Show

Type "bouncer clone https://github.com/octocat/Hello-World"
Sleep 600ms
Enter
# On a machine where Snyk is signed in, git-bouncer offers it (it uses your Snyk quota). Declined here.
Wait+Screen@120s /Snyk is set up/
Sleep 1.5s
Type "n"
Enter
Wait+Screen@60s /Let it in\?/
Sleep 1.5s
Type "y"
Enter
Wait+Screen@60s /Cloned into/
Sleep 1s
Type "ls Hello-World"
Enter
Sleep 4s
