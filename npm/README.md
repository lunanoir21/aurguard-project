# aurguard

> AUR package security guard — analyze before you install.

This is a thin launcher with **no install script**. The prebuilt `aurguard`
binary ships as a platform-specific optional dependency, so npm installs only
the one matching your os/cpu — nothing is downloaded or executed at install
time (no `postinstall`, no remote-code surface). Zero runtime dependencies.

```sh
npm install -g aurguard
aurguard --setup        # pick language + policy
aurguard -I yay         # security report
aurguard -S <package>   # analyze + install
```

Linux only (the AUR is Arch-specific). Requires `git` and `makepkg` to install
packages; analysis works without them.

Full documentation: https://github.com/lunanoir21/aurguard-project
