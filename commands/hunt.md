---
name: hunt
description: Hunt a specific vulnerability class on an authorized target using Cybergrok playbooks.
argument-hint: "<target> <skill-or-class>"
---

Hunt `$ARGUMENTS` (target plus class or skill name).

Load the matching `skills/` playbook (`hunt-idor`, `hunt-xss`, `hunt-ssrf`,
…). Confirm only with differential proof. Write
`reports/<SLUG>/findings/<severity>_<name>.md` and a PoC when proven.
