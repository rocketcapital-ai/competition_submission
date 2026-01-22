## [dev]
- code restructure to allow python packaging
- ci: add static code analysis (pylint)
- add requirements.txt to specify dependencies
- port to recent web3 version, which allows using newer Python versions
- code cleanup (import statements, type hints, pylint warning, ..)

## [0.2.0] - 2025-03-26
### Added
- Support for delegate-staking feature in new competition contracts.
- Support for performing ERC20 approvals.

### Changed
- Updated existing functions to support ERC20 approvals.
- No more need to place submission file in a particular directory. Submission file can be placed anywhere but this path must be provided to the `submit` or `stakeAndSubmit` function.

## [0.2.1] - 2026-01-09
### Changed
- More robust handling of polygon gas price calculations.

## [0.2.2] - 2026-01-14
### Changed
- Allow access to the `Delegate` module.

## [0.2.3] - 2026-01-22
### Added
- Support for downloading weekly datasets.