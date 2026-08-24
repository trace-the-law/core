# Security Policy

## Reporting a vulnerability

Do not report vulnerabilities, credentials, private data, sealed material, or
exploitation details in a public issue or pull request.

Use GitHub's **Report a vulnerability** option in the repository's Security tab
when private vulnerability reporting is enabled. Repository owners must enable
that feature before a public service or automated correction intake launches.
If the option is absent, the project does not yet provide a safe disclosure
channel; do not disclose the vulnerability publicly. No contact email is listed
until a monitored project address exists.

Privacy and legal-removal requests follow [PRIVACY.md](PRIVACY.md), not the
security-reporting route unless they also expose a security vulnerability.

## What to include privately

Provide the affected component or artifact, impact, reproducible steps, and the
smallest safe proof. Remove real credentials and unnecessary personal or case
data. State whether the issue is being actively exploited or has a disclosure
deadline.

## Security scope

Security reports include:

- authentication, authorisation, secret, or maintainer-account compromise;
- a way to bypass review and alter legal-force, effective-date, rights, privacy,
  or coverage records;
- malicious source documents, parser exploits, archive traversal, or unsafe file
  handling;
- server-side request forgery or internal-network access through submitted URLs;
- prompt injection or data poisoning that can trigger an agent or automation to
  modify the archive;
- correction-intake spam, identity leakage, or unauthorised public issue
  creation;
- exposure or re-identification of protected people; and
- integrity failures in hashes, provenance, signatures, or version history.

A disagreement with a legal classification is a correction, not a security
vulnerability, unless it demonstrates a way to bypass controls at scale.

## Required controls

Source documents, extracted text, issue bodies, URLs, and agent output are
untrusted input. Implementations must:

- sandbox parsers and converters and limit time, memory, archive depth, and file
  size;
- validate file type independently of name or declared content type;
- prevent submitted URLs from reaching private, local, metadata, or otherwise
  restricted network addresses;
- never execute instructions embedded in a source document or correction body;
- keep ingestion, review, and publication credentials separate;
- use short-lived, least-privilege GitHub App credentials rather than a broad
  personal access token;
- ensure anonymous or agent-generated reports cannot trigger workflows, merge
  changes, mention arbitrary users, or publish unsanitised text;
- require the human approvals in [GOVERNANCE.md](GOVERNANCE.md); and
- protect audit and provenance records from ordinary content-editing roles.

No secret may be committed to Git, examples, fixtures, issues, or logs.

## Response and disclosure

Security maintainers will assess a private report, restrict access to people
needed for remediation, and coordinate disclosure after a fix or mitigation.
Public advisories should credit the reporter if requested and safe, describe the
impact and affected versions, and omit exploit or personal details that would
create new harm.

Security fixes may use the emergency process in [GOVERNANCE.md](GOVERNANCE.md).
No response-time promise is made until the project has a staffed security rota.
