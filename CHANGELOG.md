# Change Log
All notable changes to this project will be documented in this file.

## Unreleased
### Changed
- Rewriting in C++ with ncursesw as the user interface

## 1.1.3.1 - 2015-01-29
### Added
- Makefile file
- src directory
- Description to README.md

### Changed
- Moved source (.go) files to newly created src directory
- Renamed CHANGELOG.txt to CHANGELOG.md
- CHANGELOG.md's syntax
- Dependencies to Build Dependencies in README.md
- Organized the order of README.md's sections

### Removed
- INSTALL.sh and UNINSTALL.sh files

### Fixed
- Build to Install and Install to Uninstall in README.md
- Typo in Manual Page

## 1.1.3.0 - 2015-01-25
### Added
- Wide character support (East Asian Characters)

### Changed
- Split latchbox.go into multiple files to make editing easier.

### Fixed
-  inString function bug for string to find larger than 2 characters long
- "~/" in location names for import, export, read, write, and keyfiles
- Typo from "Input Password" to "Input Passphrase"
- Bug that wouldn't allow for "\" in group names of imported CSV files.

## 1.0.3.1 - 2015-01-05
### Added
- INSTALL.sh and UNINSTALL.sh scripts
- Manual Page
- THIRD-PARTY-LICENSES file
- Set the ability to use --help and --version flags (-h -v)

## 1.0.3.0 - 2014-06-24
### Added
- Initial release
