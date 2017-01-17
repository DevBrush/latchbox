# Change Log
All notable changes to this project will be documented in this file.

## 2.0.0 - 2017-01-17
### Added
- Requirement of gb to compile
- latchbox-spec.txt file in docs folder
- Third party code using gb-vendor

### Changed
- doc folder to docs folder
- src folder content moved to src/latchbox
- AES mode to GCM
- Key derivation function to PBKDF2
- README.md file content to reflect the changes
- Makefile

### Removed
- imports folder
- Support for versions under 2.0.0

## 1.3.3.4 - 2016-06-11
### Added
- Option to change Work Factor for bcrypt in config file
- License text to man page
- Language involving modifying Work Factor in README.md and man page
- Quit with error message if user does not have read access to config file

## 1.3.3.3 - 2016-06-10
### Changed
- Replaced DevBrush references with PawnTakesQueen for imports and Makefile

## 1.3.3.2 - 2016-06-10
### Changed
- Fixed credits in man file

## 1.3.3.1 - 2016-06-10
### Changed
- "Dev Brush Technology" credits to "Vi Grey" credits in all files
- Modified website and email in README.md file
- Added 2016 to credits

## 1.3.3.0 - 2016-06-02
### Added
- hashKeyLegacy function
- Will create key with hashKeyLegacy function if hashKey doesn't work

### Changed
- hashKey SHA256 hashing of bcrypt now only hashes 31 byte hash of bcrypt
- Security information on README.md to discuss change in hashing key
- All mentions of AES256 and AES-256 replaced with AES256-CBC in README.md

## 1.1.3.2 - 2015-05-17
### Changed
- "Latchbox" to "LatchBox" in src/latchbox.go
- "Vi Grey" credits to "Dev Brush Technology" credits in all files
- Fixed missing space typo in src/latchbox.go

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
