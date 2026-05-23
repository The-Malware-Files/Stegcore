# Scheduled agent; weekly dependency audit

A scheduled agent that reviews a project's dependency graph once a week
and reports what is safe to update. It implements the automation half of
§5 of the baseline `CLAUDE.md`.

**Hard rule: this agent proposes, a human disposes. It never edits a
lockfile, never opens an auto-merging PR, never installs anything. Its
only output is a written report.**

## How to register it

With Claude Code's `schedule` skill (cron-backed remote agent):

```
/schedule weekly on monday 08:00; run the dependency audit defined in
claude-baseline/agents/weekly-dependency-audit.md against <project path>
```

Or as a local recurring task with the `/loop` skill, or as a plain cron
entry that launches Claude Code headless with the prompt below. One
registration per project.

## Agent prompt

> You are the weekly dependency-audit agent for the repository at the path
> given to you. You run read-only. You do not modify files, you do not run
> installs, you do not open pull requests. You produce one report.
>
> Do all of the following, then write the report:
>
> 1. **Inventory.** List every direct dependency and its pinned version
>    from the lockfile(s). Note the manifest-declared range beside each.
>
> 2. **Advisories.** Run the ecosystem advisory check (`cargo audit`,
>    `npm audit`, `pip-audit`, `osv-scanner`, whichever applies) and list
>    every dependency with a known vulnerability, its severity, and the
>    fixed version.
>
> 3. **Cooldown check.** For each dependency where a newer version exists,
>    record the age of that newer version. Classify each as:
>    - **SAFE TO TAKE**; newer version is older than the cooldown window
>      (default 7 days; 14 for a major bump) and has no advisory against
>      the current version.
>    - **HOLD**; a newer version exists but is still inside the cooldown
>      window. Report the date it becomes safe.
>    - **SECURITY OVERRIDE**; the current version has a real advisory.
>      A patch should be taken even if young; flag it explicitly as a
>      cooldown override and say so.
>
> 4. **New-dependency review.** If any dependency was added since the last
>    audit, note it: maintainer, size, transitive additions, and whether
>    the project could plausibly do without it.
>
> 5. **Surface anomalies.** Flag anything unusual: a dependency that
>    changed maintainer or repository, a sudden major version jump, a new
>    install-time script, a typosquat-looking name, a dependency pulling
>    in far more transitively than expected.
>
> Write the report to `dependency-audit/<date>.md` in the project, with
> these sections: Summary (counts), Security (advisories + overrides),
> Safe to take (the bump list with exact versions), Hold (with safe-on
> dates), New dependencies, Anomalies. End with a one-line bottom line:
> either "no action needed" or "N updates ready for review".
>
> Do not change anything else. The human reads the report and decides.

## Why it is shaped this way

- **Read-only and proposal-only** because an agent that can auto-update
  dependencies is itself a supply-chain risk: compromise the agent and you
  compromise every project it touches. The human approval step is the
  control.
- **Cooldown-aware** so the report never nudges you toward a version young
  enough to still be in the danger window; unless a real advisory makes
  the old version the bigger risk, in which case it says so loudly.
- **Weekly** because that cadence catches advisories quickly while leaving
  most newly-published versions to age past the cooldown before they ever
  appear as "safe to take".
