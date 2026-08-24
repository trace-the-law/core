# GitHub organization setup

**Default: create the organization as `trace-the-law`, then publish this
repository as `core`.** Confirm the handle in GitHub's creation flow; a missing
profile page does not guarantee that a name can be registered.

Do not create the organization, push this repository, or install an integration
from an unattended agent. These are owner actions with lasting access and
identity consequences.

## Initial repositories

```text
trace-the-law/.github          Organization profile and community defaults
trace-the-law/core             This repository
trace-the-law/source-registry  Global authority and source discovery records
trace-the-law/india            First country corpus and India GST adapter
```

Keep subnational material in the country corpus initially. Do not create topic
repositories such as `tax` or `constitutional-law`; cross-topic authority is a
core graph requirement.

## Organization controls

Before inviting contributors:

1. Add at least two human owners and store account-recovery material safely.
2. Require two-factor authentication using secure methods for members and
   outside collaborators. GitHub documents the current control in
   [Requiring two-factor authentication in your organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization).
3. Set the default member permission to read. Restrict repository creation,
   deletion, visibility changes, and integration installation to owners.
4. Prefer narrowly scoped GitHub Apps over personal access tokens or shared bot
   accounts. Keep ingestion, correction-issue, pull-request, and publication
   credentials separate.
5. Review the organization audit log and installed integrations on a regular
   schedule.

## `main` ruleset

Apply a repository ruleset to `main`:

- require pull requests and two human approvals;
- dismiss stale approvals and require approval of the latest reviewable push;
- require all review conversations to be resolved;
- require the `validate` status check;
- block force pushes and branch deletion;
- prevent the author from approving their own change; and
- give no routine bypass to bots.

The two-approval default is deliberately stricter than routine-change
governance. It enforces the high-impact rule until the project has a tested way
to apply stronger review only to legal-force, coverage, rights, privacy, and
policy paths. GitHub's current rule options are described in
[Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets).

Add a required DCO sign-off check before accepting outside contributions. Do
not commit or push this uncommitted scaffold under another person's sign-off.

## Private reporting and automation

Keep factual-correction issues, correction receipts, invalidation events, and
post-genesis corpus snapshots disabled until this section is complete and the
base policy switch is replaced by a reviewed verifier configuration. A report's
URL and `created_by_project_bot: true` field are not authentication.

Before public ingestion or a correction service launches:

- enable private vulnerability reporting and verify that monitored maintainers
  receive its notifications; see
  [Configuring private vulnerability reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository);
- publish separate monitored privacy and legal-removal routes;
- add those real routes to `.github/ISSUE_TEMPLATE/config.yml` and the public
  site only after they work;
- give the correction broker no GitHub credential;
- give the issue bot only issue-write access and no contents access; and
- verify bot identity, repository identity, issue payload digest, publication
  time, merge commit, and snapshot receipt against GitHub rather than trusting
  fields supplied inside a report; and
- ensure no report can trigger a workflow, mention arbitrary accounts, create a
  pull request, or mutate corpus data.

## First publication sequence

1. Create the organization and add the second owner.
2. Create an empty public `core` repository without generated files.
3. Review this local tree and make the initial signed-off commit under the
   owner's identity.
4. Push `main`, enable the ruleset and security controls, then test them with a
   disposable pull request.
5. Publish the organization profile and monitored reporting routes.
6. Only then start the bounded pilot in a separate corpus repository.
