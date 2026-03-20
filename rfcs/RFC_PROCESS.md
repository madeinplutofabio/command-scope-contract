# RFC Process

## Overview

CSC uses an RFC (Request for Comments) process for protocol changes and significant design decisions. This ensures that important decisions are documented, reviewable, and traceable.

## Lifecycle

Each RFC progresses through the following states:

1. **draft** — under active development, open for discussion
2. **review** — submitted for formal review by maintainers
3. **accepted** — approved in substance, ready for implementation or incorporation into the spec
4. **final** — frozen artifact; no normative changes without a new or superseding RFC
5. **superseded** — replaced by a newer RFC
6. **rejected** — closed without adoption

## File naming

RFCs are stored in the `rfcs/` directory with the naming convention `NNNN-short-title.md`.

For example: `0001-csc-core.md`

## RFC structure

Each RFC should include:

- **Title**
- **Status** (`draft`, `review`, `accepted`, `final`, `superseded`, `rejected`)
- **Author(s)**
- **Created date**
- **Summary** — one-paragraph description
- **Motivation** — why this change is needed
- **Design** — detailed proposal
- **Alternatives considered**
- **Open questions**

## Review and approval

- RFCs must be submitted as pull requests.
- Discussion happens on the pull request.
- RFC review follows [GOVERNANCE.md](../GOVERNANCE.md).

Current default rule:

- at least one maintainer review for `review`
- normative RFCs should receive two maintainer approvals before `accepted` where maintainer count allows
- if fewer than two maintainers are active, the active maintainers may approve under the project's current governance model

## Artifact integrity

### Drafts

Drafts use Git history for version tracking. No additional hashing is required during the draft and review phases.

### Accepted and final RFCs

Once an RFC reaches **accepted** or **final** status:

1. Compute a canonical SHA-256 hash of the RFC file contents.
2. Record the hash in `rfcs/index.yaml` alongside the RFC metadata.
3. Tag the commit or release that finalizes the RFC artifact when appropriate.

### Milestone RFCs

For major protocol RFCs (for example, core protocol, conformance, governance):

1. Archive on [Zenodo](https://zenodo.org/) to create a stable, citable artifact.
2. Record the DOI in `rfcs/index.yaml`.
3. Reference the DOI from the README or relevant documentation.

This follows the precedent established by PIC for protocol artifact integrity.

## Rationale

Drafts need version control. Final RFCs need artifact identity.

This separation keeps the editing workflow lightweight while providing strong provenance for stable protocol documents.
