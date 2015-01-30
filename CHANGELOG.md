# Change Log
All notable changes to this project will be documented in this file.

## Unreleased
### Changed
- Rewriting to C++

## 1.1.3.1 - 2015-01-29
### Added
- Added Makefile file
- Created src directory

### Changed
- Moved .go files to newly created src directory
- Changed CHANGELOG.txt to CHANGELOG.md
- Rewrote CHANGELOG.md's syntax

### Removed
- Removed INSTALL.sh and UNINSTALL.sh files

## 1.1.3.0 - 2015-01-25
### Added
- Wide character support (East Asian Characters)

### Changed
- Split latchbox.go into multiple files to make editing easier.

### Fixed
- Fixed inString function bug for string to find larger than 2 characters long
- Fixed ~/ in location names for import, export, read, write, and keyfiles
- Fixed typo from "Input Password" to "Input Passphrase"
- Fixed bug that wouldn't allow for "\" in group names of imported CSV files.

## 1.0.3.1 - 2015-01-05
### Added
- Included Install and Uninstall scripts
- Included man page
- Wrote THIRD-PARTY-LICENSES file
- Set the ability to use --help and --version flags (-h -v)

## 1.0.3.0 - 2014-06-24
### Added
- Initial release
