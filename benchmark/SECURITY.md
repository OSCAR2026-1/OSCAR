# Security

OSCAR-Benchmark intentionally runs vulnerable software versions. Run it
only in disposable, isolated environments with the network, mounts,
capabilities, user, and read-only settings declared by each case contract.

Never provide production credentials, host secrets, unrelated host mounts, or
unrestricted network access. Report benchmark packaging or isolation issues
through the security contact configured on the eventual public repository.

The `GH-P4-002` case contains a test-only TLS certificate key used by its
container-local HTTPS boundary. The vulnerable and fixed copies are identical,
are never trusted outside that isolated fixture, and are admitted by the
release auditor only at two exact paths with SHA-256
`7633ece344af7d6e1e9fecf574ebdbd82bde5124f612058262c2bfd2472972f9`.
Any additional or modified private-key material fails the release audit.
