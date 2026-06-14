# aurguard

> AUR package security guard — analyze before you install.

This is the npm wrapper. On install it downloads the prebuilt `aurguard` binary
for your platform from GitHub Releases.

```sh
npm install -g aurguard
aurguard --setup        # pick language + policy
aurguard -I yay         # security report
aurguard -S <package>   # analyze + install
```

Linux only (the AUR is Arch-specific). Requires `git` and `makepkg` to install
packages; analysis works without them.

Full documentation: https://github.com/aurguard/aurguard
