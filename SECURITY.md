# Security policy

`mitrity-go` sits between a Go agent's tool execution and the MITRITY edge
that governs it. A bug here can turn a deny into a run, so we treat every
report as high priority.

## Reporting a vulnerability

Email **soc@mitrity.com**. Do not open a public issue for anything that could
let a tool call bypass admission, leak the admission token, or make the
adapter report coverage it does not have.

Please include the module version (`go list -m github.com/mitrity-io/mitrity-go`,
or the `mitrity.Version` constant your binary was built with), the Go version,
a minimal reproduction, and what the edge answered (or did not).

We acknowledge reports within two business days and keep you informed until
the fix ships. Coordinated disclosure is welcome; we ask for 90 days.

## Supported versions

Only the latest minor release receives security fixes. The admission protocol
version an adapter release speaks is recorded in
[iag-specs/sentinel/adapters.md](https://github.com/mitrity-io/iag-specs/blob/main/sentinel/adapters.md).

## What is and is not a vulnerability here

- A tool call that runs after the edge answered `deny` or `held`, or after the
  edge could not be reached: **vulnerability**.
- The admission token appearing in a log line, an error message, an
  environment variable the adapter sets, or a command line: **vulnerability**.
- An attestation that claims a tool is hooked when it is not: **vulnerability**.
- A policy that allows something you did not expect: a policy question for
  your MITRITY console, not an adapter defect.
