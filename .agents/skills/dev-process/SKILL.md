---
name: dev-process
description: Dev process for this project — delegate to subagents, preserve stack splits, verify each layer, and run an adversarial review before committing.
---

# Dev Process

Follow this process for work in this repository.

## Delegate by default

- For any multi-step, multi-file, or parallelizable task, delegate bounded subtasks to subagents instead of doing all work inline. Keep the main thread for planning, synthesis, review, and git operations.
- Size fan-out to genuinely independent subtasks. Batch related small queries into one child rather than spawning one child per file, keyword, or directory.
- A single focused edit, a one-file lookup, or a quick check stays inline.
- Parallel children that may write must use isolated worktrees. Sequential layers that build on each other's changes run one at a time in the shared checkout. Never let two writers edit the same checkout concurrently.
- After spawning, wait for or read the child result instead of repeating its work. A timeout means the child is still running — do not duplicate its task.

## Stack discipline

- Write commit messages in Conventional Commits format: `type(scope): description` (for example `feat(upstream): add pull-through index`). Use `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, or `ci` as the type, and append the stack position after the description when the commit belongs to a stack (for example `feat(upstream): add pull-through index (stack 1/3)`).
- When a plan divides work into separate diffs, commits, branches, or PRs, preserve that split exactly and in order. Commit each planned layer separately, even when one combined commit would satisfy the request.
- Commit landed, verified work before moving on to the next layer or task. Do not let multiple layers pile up uncommitted in one tree.
- If work for several layers already sits in one tree, split it at commit time by layer (by file, or by hunk with `git add -p` when a file spans layers).
- Commit, push, and PR creation each need the user's explicit ask for that exact write. Implementation alone is not authorization to publish. When creating PRs for a stack, link every layer to the thread.

## Verify before committing

- Before committing a layer, run the project gates and watch them pass: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --locked`. Do not commit a layer whose relevant tests were never run in this session.
- Reproduce reported failures against the real code before fixing, and fix the root cause at the smallest correct scope.
- Report test evidence actually observed (commands and results), never a copied or assumed pass.

## Adversarial reviewer pass

- After a layer's implementation and gates pass, delegate one independent reviewer subagent before committing. The reviewer must not be the child that wrote the code.
- Give the reviewer the diff and a concrete falsification target per success criterion (correctness, edge/error paths, and contract drift), and require it to cite file and line evidence for every claim.
- Fix every load-bearing finding, or record it explicitly as accepted with a reason. Re-run the gates after fixes. Do not commit while a load-bearing review finding is open.
