Minimum valid commit line

fix(networking): correct DNS SRV lookup

Feature with body

feat(k8s): add Cilium network policy support

- default deny-all ingress/egress
- egress allow-list for kube-system

Breaking change (footer variant)

refactor(tofu): rename output variables

BREAKING CHANGE: destroys and recreates all outputs; state import needed.

Breaking change (shorthand !)

feat!: switch authentication to JWT

---

What NOT to do

Omit the type or the colon. Example wrong: update: make things faster → ignored.

Capitalise type. Example wrong: Fix: → ignored (types are case-insensitive in the spec but release-please’s regex assumes lower-case).

Forget the blank line before body or footer.

Put a trailing period in the description.

---

Why these rules matter

release-please’s versioning engine (DefaultVersioningStrategy) maps exactly feat, fix, BREAKING CHANGE/! to minor, patch, major bumps.

Every other type is only cosmetic unless you add ! or a BREAKING CHANGE footer.

If a commit does not match the pattern ^(\w+)([\w\-]+)?(!)?:\s.+, release-please ignores it entirely.

Follow this table and all commits will be parsed, changelogs will be rich, and semantic version bumps will be automatic.
