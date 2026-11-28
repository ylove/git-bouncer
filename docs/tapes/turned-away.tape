# Regenerate: from a checkout of the repo, run   BOUNCER_REPO="$PWD" vhs docs/tapes/turned-away.tape
Output site/img/turned-away.gif
Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 620
Set Padding 24
Set TypingSpeed 45ms
Set Theme "GitHub Dark"

Hide
Type `alias bouncer='node "$BOUNCER_REPO/bin/bouncer.js"'; cd "$(mktemp -d)"; clear`
Enter
Show

Type "bouncer scan github.com/micr0s0ft/vscode"
Sleep 600ms
Enter
Wait+Screen@30s /nothing was downloaded/
Sleep 4s
