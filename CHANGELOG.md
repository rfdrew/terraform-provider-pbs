# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Provider configuration: an API token or a username and password, TLS
  pinned by certificate fingerprint, a CA file or no verification, node name,
  request and task timeouts, all also from `PBS_*` environment variables.
- `pbs_version` data source: the server's release.
- `pbs_fingerprint` data source: the SHA-256 fingerprint of the certificate
  the server serves, with its subject and validity.
