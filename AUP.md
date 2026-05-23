# Acceptable Use Policy

> **Version:** 1.0 (effective 2026-05-23)
> **Applies to:** Stegcore CLI, GUI and engine — all releases from v4.0.1 onward.
> **Licence:** This document is part of Stegcore and ships under the same AGPL-3.0-or-later terms.

Stegcore is a steganography and steganalysis toolkit. It is dual-use by
nature, in the same sense that **Nmap**, **Hydra**, **Wireshark** and
**Metasploit** are dual-use: capabilities a defender needs to do their job
are, by construction, capabilities an attacker can misuse. The honest
response is not to pretend otherwise — it is to be explicit about who the
tool is for, what the gates are, and what is out of bounds.

The intent of this AUP is to make that contract legible, both for users who
want to know they are using the tool legitimately, and for organisations,
journalists, courts, employers and the wider security community who want
to know how Stegcore frames its surface.

## §1 — Who Stegcore is for

Stegcore is built for:

- **Journalists** protecting sources from state-level surveillance.
- **Activists** in jurisdictions where political speech is criminalised.
- **Security researchers** studying real-world steganography techniques.
- **Digital forensics professionals** triaging suspected stego carriers
  in investigations.
- **Red teams and pentesters** validating egress controls and DLP
  coverage during authorised engagements.
- **CTF players and educators** practising the skills.
- **Privacy-conscious individuals** exercising their right to keep
  personal correspondence and records private from third-party scraping.

If you are not one of those, Stegcore is probably not the right tool for
your problem. There are easier ways to send a private message.

## §2 — Prohibited uses

You may not use Stegcore to:

1. **Conceal illegal content** — child sexual abuse material, content
   produced by trafficking, content that depicts non-consensual sexual
   acts, or any other content whose possession is itself a crime.
2. **Distribute malware** — Stegcore must not be used as a delivery
   mechanism for code intended to compromise systems the operator is not
   authorised to compromise.
3. **Compromise systems without authorisation** — using the covert-channel
   surface (v6+) against networks you have not been contracted, employed
   or explicitly permitted to test.
4. **Circumvent lawful investigations** — Stegcore is not a tool to defeat
   warrants, court orders or lawful interception within a rule-of-law
   framework. (This is distinct from defending against surveillance in
   authoritarian jurisdictions; see §1.)
5. **Conceal communications relating to terrorism or organised crime** —
   no good-faith use case requires this; if you think you have one, you
   need a lawyer, not a steganography toolkit.
6. **Harass, dox or stalk** — embedding hidden tracking content in files
   intended for another person without their knowledge or consent.
7. **Defraud** — embedding hidden manipulated documents in chain-of-
   custody material, or otherwise undermining evidentiary integrity in
   civil or criminal proceedings.

The developers do not condone misuse, do not provide support to misuse,
and reserve the right to publicly disassociate from any project, fork or
deployment that materially advances any of the above.

## §3 — Dual-use surfaces and gates

Some Stegcore subcommands are dual-use by construction. Each ships behind
a documented gate. The gates are not technical drm — they exist so a user
cannot run a high-risk operation accidentally, and so the operation
records that the user explicitly invoked it.

### §3.1 — `stegcore brute-force` (planned v5)

Stegcore will ship a unified password-recovery engine for embedded
steganography payloads, covering Steghide (CVE-2021-27211 32-bit seed),
OpenStego (Random-LSB mode) and forward-compatible additions.

**Gate.** The command refuses to run without `--i-am-authorised`. When
the flag is supplied, the report records:

- the exact invocation string
- the operator's `whoami` and hostname
- a timestamp
- a SHA-256 of the input file
- the discovered seed / passphrase (or "not recovered")

**Forensic mode.** `--seed-only` returns the recovered seed without
extracting the payload — useful for chain-of-custody work where the
investigator should hand both the artefact and the recovery method to
the next custodian without contaminating the payload.

**Why ship it at all.** Stegcracker and Stegseek already exist under GPL.
Not shipping the capability hands the ground to less-careful actors and
leaves Stegcore as a half-tool — *detection* without *attribution* is
limited investigatory value. The gate is the discipline.

### §3.2 — Covert-channel embedders (planned v6)

Stegcore will ship embedders for DNS, ICMP and HTTPS-timing covert
channels, paired with a `stegcore detect-covert` companion that takes
PCAPs and flags candidate exfiltration patterns.

**Gate.** All embedder subcommands require `--i-am-authorised` and a
signed manifest file (`--engagement-manifest <path>`) describing the
authorised target network, the timeframe, and the authorising party.
The manifest must be signed by a key the operator controls; the
signature and manifest hash are recorded in every emitted packet's
local log.

The HTTPS-timing surface additionally requires `--research-only` and
will refuse to run against any host whose TLS certificate name resolves
to a public IP not on a documented allowlist.

**Why ship it at all.** "You cannot detect what you cannot generate."
Detector research needs ground-truth datasets, SOC validation needs
exercisable scenarios, and the wild already has dnscat2 and iodine.
Stegcore's contribution is the unified embedder+detector pair behind a
single auditable gate.

### §3.3 — Document watermarking (planned v5)

Document watermarking (PDF / PNG / Word / PPT) is offered for legitimate
provenance tracking — e.g. a journalist watermarking source-tracking
copies before distribution, or a publisher pre-watermarking review PDFs.

**Gate.** When the carrier is a document (as opposed to a research
artefact), Stegcore will display a consent reminder and require
`--consent-recorded` confirming that either (a) you control the
document being watermarked, or (b) the recipients have been informed
that the document carries a tracking watermark. This is not
technically enforceable; it is a written record that you understood
the surface.

### §3.4 — AUP-enforcement hardening (planned v8)

Once the toolkit has the surfaces above, Stegcore will ship a structural
enforcement layer:

- **`.stegcore-policy.toml`** — an organisation-level policy file that
  can disable specific subcommands on managed installs (e.g. a
  newsroom IT team disabling `brute-force` for non-investigation
  desks).
- **Signed manifests required by default** for high-risk subcommands;
  the unsigned escape hatch survives but logs more loudly.
- **Reporting channel** — see §4.

## §4 — Reporting misuse

If you become aware of Stegcore being used in a way that materially
advances any of the prohibited uses in §2, you can report it to:

- **Email:** abuse@themalwarefiles.com  (PGP key fingerprint published
  on danieliwugo.com — verify before sending sensitive material).
- **GitHub:** open a private security advisory on
  `github.com/The-Malware-Files/Stegcore` (preferred for technical
  abuse — supply-chain, malicious fork, etc.).

The developers will respond within a reasonable timeframe (target: 5
business days). We are a single-developer project and cannot guarantee
investigative resources; what we can guarantee is public
disassociation, takedown of any abusive fork hosted under our orgs, and
co-operation with law enforcement requests that come through proper
channels with jurisdiction.

We will not respond to:

- Demands to assist in defeating legitimate end-user privacy.
- Requests to backdoor the tool for any agency, jurisdiction or
  buyer.
- Demands that we add identifying telemetry to Stegcore
  installations.

## §5 — On dual-use, plainly

Steganography is a tool capable of both great harm and great good. So is
cryptography. So is the internet. So is a kitchen knife. The case for
shipping Stegcore openly is the same case made for Nmap, Hydra,
Wireshark and Metasploit a generation ago: *the defensive community
needs the capability more than the offensive community does*, because
the offensive community already has it.

Steganography in particular is poorly understood by the public, by
courts, and by most security teams. A widely-available, calibrated,
honest open-source toolkit that explains what it does and ships a
working AUP is the single best argument against bad-faith
steganography-related policy. We would rather Stegcore be cited in
that conversation than absent from it.

If you want to use Stegcore for legitimate work, welcome. If you want
to use it for the things in §2, please go away.

## §6 — Changes to this AUP

This document is versioned. Changes are tracked in git and the version
number at the top of the file is bumped on each substantive change. The
in-product AUP shown by the Installer at first run mirrors this
document; if the two diverge, the canonical text is this file.

---

*Stegcore is developed by Daniel Iwugo / The Malware Files. The
project's strategic stance is documented in
[private/plans/roadmap.md](private/plans/roadmap.md) (private). The
in-product AUP step lives in
[frontend/src/components/Installer.tsx](frontend/src/components/Installer.tsx)
(`StepAUP`); changes to the canonical text should propagate there on
the next release cut.*
