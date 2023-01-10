# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.1.0] - 2023-01-11

This version is compatible with [SimpleSAMLphp v1.17](https://simplesamlphp.org/docs/1.17/simplesamlphp-changelog)

### Changed

- COmanageDbClientCertEntitlement
  - Convert output from JSON Object to JSON Array
- COmanageDbClient
  - Change table name to `cm_voms_members`

## [v2.0.0] - 2021-01-22

This version is compatible with [SimpleSAMLphp v1.17](https://simplesamlphp.org/docs/1.17/simplesamlphp-changelog)

### Changed

- Comply to [PSR-4: Autoloader](https://www.php-fig.org/psr/psr-4/) guidelines
- Comply to [PSR-12: Extended Coding Style](https://www.php-fig.org/psr/psr-12/) guidelines
- Apply modern array syntax to comply with [SimpleSAMLphp v1.17](https://simplesamlphp.org/docs/stable/simplesamlphp-upgrade-notes-1.17)

## [v1.0.0] - 2020-11-11

This version is compatible with
[SimpleSAMLphp v1.14](https://simplesamlphp.org/docs/1.14/simplesamlphp-changelog)

### Added

- COmanageDbClient class
  - Create entitlements using the user information retrieved by VOMS
- COmanageDbClientCertEntitlement
  - Create an attribute based on `cert_entitlement` scheme using the information retrieved by VOMS
