## Agent skills

### Issue tracker

Issues and PRDs for this repo live as GitHub issues. See [`docs/agents/issue-tracker.md`](docs/agents/issue-tracker.md).

### Triage labels

Triage labels use the standard vocabulary. See [`docs/agents/triage-labels.md`](docs/agents/triage-labels.md).

### Domain docs

Single-context layout. See [`docs/agents/domain.md`](docs/agents/domain.md).

## Guidelines

When making major decisions, ask before proceeding. Do not guess.

Be opportunistic in using open source libraries. Choose well-established packages with permissive licenses. Prefer to use a library over writing new code, especially if:

- the future direction of this component will greatly benefit from the broader scope of capabilities provided by the library;
- cryptographic algorithms are involved;
- wire protocols are involved --- code should focus on API concerns such as methods and schemas for data structures, not network transport and serialization.

When uncertain about future direction, ask before proceeding. Do not guess.
