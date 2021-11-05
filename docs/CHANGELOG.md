# Changelog

All notable changes between versions will be listed below.

The format of this file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

The project follows to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/ventaquil/chksum/compare/v0.1.0-rc0...)

### Added
- Added support for multiple versions and OSes in GitHub workflow.

### Changed
- Changed GitHub workflow to use `actions-rs`.

## [v0.1.0-rc0](https://github.com/ventaquil/chksum/compare/v0.0.0...v0.1.0-rc0) - 2021-11-04

### Added
- Added GitHub workflow to test changes on `master` branch.
- Added Makefile which allows to build, test and install binary as well as autocompletion script and manpage.
- Added experimental support for SIMD instructions for x86 and x86_64 architectures available via `simd` feature.
- Added `inline` feature which enables inlining of some functions (enabled by default).
- Added doctests and benchmark tests for hash algorithms.
- Added autocompletion script for fish shell.
- Added manpage of a `chksum` binary.
- Added this changelog file.
- Added docblocks for public items.

### Changed
- Changed Rust Edition from 2018 to 2021.
- Changed public library interface to be more function-like instead of structure-like.
- Changed internal structure of implemented hash algorithms (divided into `State` and `Hash` structures which are generics right now).
- Changed test cases for hash algorithms.
- Changed short long name of CLI option which allows to use paths to calculate digests.
- Changed year in license file.
- Changed examples in README file.

### Removed
- Dropped support for multithreading in CLI application.

## v0.0.0 - 2020-05-23

### Added
- Added MD5 and SHA-1 hash algorithms.
- Added context-like external API.
- Added basic unittests for structures in `hash` module.
- Added CLI program which allows to calculate digest of files or directories under given paths.
- Added chunk size option in CLI which determines size of the internal buffer used to load data from filesystem.
- Added CLI option which allows to choose between hash algorithms.
- Added support for multithreading for CLI application along with option to determine maximum number of concurrent worker threads.
- Added license and README files.
