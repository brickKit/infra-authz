[English](AGENTS.md) · [中文](AGENTS.zh.md)

# infra/authz

The AI guide to developing this component. How to use it, its boundaries and contracts: BRICKKIT.md. Dependencies, configuration and deployment: component.yaml.

## Code map

<!-- TODO: two tables — "Path / Owns" (paths in backticks, directories ending in /) and "Feature / Start here / Then"; brickkit lint checks every path exists -->

## Build and test

<!-- TODO: the exact commands to build, test, run locally and check the contract, and what success looks like -->

## Design decisions

<!-- TODO: why it does not depend on some other component; alternatives rejected and why — longer reasoning goes in docs/ and is linked here -->

## Pitfalls

<!-- TODO: a table: Never / Symptom / Why — only what is specific to this component; project-wide rules stay in the project's AGENTS.md -->

## Before changing code

<!-- TODO: 3 to 8 checks to run before changing code here -->

<!-- brickkit:managed:begin lang=en -->
<!-- maintained by brickkit (init, add, remove, upgrade, skills update): edits between these markers are overwritten -->

## BrickKit

This is a BrickKit component: `component.yaml` is all the platform reads. The rules it relies on:

- `configSchema` keys are the environment variable names the code reads. Never use a reserved name: `COMPONENT_ID`, `COMPONENT_VERSION`, `PORT`, `BRICKKIT_SERVED_MEMBERS`, `BRICKKIT_SERVED_MEMBERS_CONFIG`, or any `*_ENDPOINT`.
- Dependencies are exact versions. A dependency's address arrives as `<ID>_ENDPOINT`; an optional dependency that is absent has no variable at all, so read it with a fallback.
- `/healthz` checks only this process, never a dependency. The migration command runs from the same image and must fail on an argument it does not know.
- `BRICKKIT.md` travels to every project that uses this component and is read there without the repository: keep it in step with the code, with no relative links.
- Release: raise `metadata.version`, commit, push, `brickkit release`. `brickkit lint` checks the manifest and these docs — inside a project, run in this directory, it checks only this component (`--all` for the whole project).
- The full rules are in the `brickkit-component` skill (`.claude/skills/brickkit-component/SKILL.md` at the root of the project or repository where skills are installed; `brickkit skills update` installs it); for flags ask `brickkit <command> --help`; BrickKit's own documentation is `brickkit docs`.
<!-- brickkit:managed:end -->
