# AI assistance in Evidentia's development

Last updated: 2026-09-05. Disclosure level: **ai-assisted** (human work completed
with AI assistance and reviewed by the maintainer before it ships).

This page records how AI tools take part in building Evidentia. It covers the
development process only. Evidentia's own AI features, the `evidentia-ai` package
and the AI-governance catalogs, are documented in
[`docs/model-risk.md`](model-risk.md) and the
[capability matrix](capability-matrix.md).

## What the maintainer does

- Sets scope, priorities and design, and decides what ships and when.
- Reviews every change before it lands, runs the release review, and performs
  every publish step personally (tags, pushes, merges, package and container
  releases).
- Writes the security dispositions, licence decisions and public statements.

## Where AI tools help

| Role in the development workflow | Tools |
|---|---|
| Coding assistants (implementation, tests, refactors, drafting docs) | Claude (Claude Code and Claude Desktop), Codex |
| Hosted models, reached through a router | OpenRouter (Gemini, GPT and others) |
| Local models | Ollama and other locally run models |
| Orchestration framework | LangChain |
| Research and source discovery | Perplexity |

The list changes as tools enter or leave the workflow; the date at the top is the
last revision. Custom infrastructure and integrations for each tool were built
in-house.

## What is excluded

- No AI identity appears in git metadata. Commits are authored and signed by the
  maintainer, and there are no `Co-authored-by` trailers naming AI tools.
- No autonomous agent opens issues or pull requests, and none publishes anything.
- No AI-drafted text ships unread. Every document, changelog entry and release
  note is reviewed and edited by the maintainer first.

## Contributors

External contributors may use AI tools under the rules in
[`CONTRIBUTING.md`](../.github/CONTRIBUTING.md): the contributor is the author and is
accountable for the change; significant AI assistance is disclosed in the pull
request description or with an `Assisted-by:` commit trailer; `Co-authored-by`
trailers naming AI tools are not accepted.

## Organisation policy

Polycentric Labs maintains one AI-assistance policy shared by its projects. This
page is Evidentia's project-level record under that policy.
