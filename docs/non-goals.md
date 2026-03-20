# Non-goals

CSC is deliberately scoped. This document clarifies what CSC is **not**.

## What CSC is not

- **Not a workflow engine.** CSC handles bounded execution batches, not multi-step orchestration.
- **Not a full IAM replacement.** CSC defines execution-boundary policy, not identity management.
- **Not a sandbox by itself.** CSC declares constraints; enforcement depends on the runtime environment.
- **Not a replacement for MCP.** MCP provides structured access to tools and external context. CSC provides bounded execution for shell and CLI actions. These are complementary.

## Clean positioning vs MCP

- **MCP**: structured access to tools and external context
- **CSC**: bounded execution for shell and CLI actions
