# aurguard demo — render with: vhs assets/demo.tape
Output assets/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1180
Set Height 940
Set Padding 26
Set Theme "TokyoNight"
Set TypingSpeed 55ms
Set PlaybackSpeed 1.0

# Put the locally-built binary on PATH without showing it.
Hide
Type "export PATH=$HOME/.local/bin:$PATH PS1='~ ❯ '"
Enter
Type "clear"
Enter
Show

# 1. Clean package — English report
Type "aurguard -I yay"
Sleep 600ms
Enter
Sleep 4s

Type "clear"
Enter
Sleep 300ms

# 2. Bare name — finds package, wraps long findings
Type "aurguard hermes"
Sleep 600ms
Enter
Sleep 4s

Type "clear"
Enter
Sleep 300ms

# 3. No exact match — suggests packages containing the name
Type "aurguard opencode"
Sleep 600ms
Enter
Sleep 4s
# cancel the interactive picker
Enter
Sleep 1s

Type "clear"
Enter
Sleep 300ms

# 4. Same report, Turkish interface
Type "aurguard -I hermes --lang tr"
Sleep 600ms
Enter
Sleep 4s

Sleep 2s
