# simplesamlphp-module-attrauthvoms

A SimpleSAMLphp module for creating entitlements using the user membership
information that has been retrived from
[VOMS](http://italiangrid.github.io/voms/documentation/voms-admin-guide/3.7.0/api.html)
and adding them to the list of attributes received from the identity provider.

In a nutshell, this module provides a set of SimpleSAMLphp authentication
procesing filters allowing to use VOMS as an Attribute Authority. Specifically,
the module supports retrieving the following user information from VOMS:

- user's certificate subject and issuer DN
- user's VO membership and role information and create ent, which is
  encapsulated in `eduPersonEntitlement` attribute values following the
  [AARC-G002](https://aarc-community.org/guidelines/aarc-g002/) specification

The information from VOMS must be stored into a SQL table, in order to eliminate
any delay in the login process. The table should contain the following columns:

```sql
CREATE TABLE vo_membership (
    id integer NOT NULL,
    subject character varying(256) NOT NULL,
    issuer character varying(256) NOT NULL,
    vo_id character varying(256) NOT NULL,
    created timestamp without time zone
);
```

## COmanage Database client

The `attrauthvoms:COmanageDbClient` authentication processing filter is
implemented as a SQL client. This module uses the SimpleSAML\Database library to
connect to the database. To configure the database connection edit the following
attributes in the `config.php`:

```php
    /*
     * Database connection string.
     * Ensure that you have the required PDO database driver installed
     * for your connection string.
     */
    'database.dsn' => 'mysql:host=localhost;dbname=saml',
    /*
     * SQL database credentials
     */
    'database.username' => 'simplesamlphp',
    'database.password' => 'secret',
```

Optionally, you can configure a database slave by editing the `database.slaves`
attribute.

### SimpleSAMLphp configuration

The following authproc filter configuration options are supported:

- `userIdAttribute`: Optional, a string containing the name of the attribute
  whose value to use for querying the COmanage Registry. Defaults to
  `distinguishedName`.
- `blacklist`: Optional, an array of strings that contains the SPs that the
  module will skip to process.
- `voBlacklist`: Optional, an array of strings that contains VOs (COUs) for
  which the module will not generate entitlements.

Note: In case you need to change the format of the entitlements you need to
modify the source code.

### Example authproc filter configuration

```php
    authproc = [
        ...
        '60' => [
            'class' => 'attrauthvoms:COmanageDbClient',
            'userIdAttribute' => 'distinguishedName',
            'blacklist' => [
                'https://www.example.org/sp',
            ],
            'voBlacklist' => [
                'vo.example.org',
            ],
        ],
```

## COmanage Database client for CertEntiltlement

The `attrauthvoms:COmanageDbClientCertEntitlement` authentication processing
filter is based on `attrauthvoms:COmanageDbClient` and creates an attribute base
on the cert_entitlement scheme.

To configure the database connection edit the following attributes in the
`config.php`:

```php
    /*
     * Database connection string.
     * Ensure that you have the required PDO database driver installed
     * for your connection string.
     */
    'database.dsn' => 'mysql:host=localhost;dbname=saml',
    /*
     * SQL database credentials
     */
    'database.username' => 'simplesamlphp',
    'database.password' => 'secret',
```

Optionally, you can configure a database slave by editing the `database.slaves`
attribute.

### SimpleSAMLphp configuration

The following authproc filter configuration options are supported:

- `userIdAttribute`: Optional, a string containing the name of the attribute
  whose value contains the user's certificate subject. Defaults to
  `distinguishedName`.
- `attributeName`: Optional, a string containing the name of the attribute whose
  value will be stored the new entitlement. Defaults to `certEntitlement`.
- `spWhitelist`: Optional, an array of strings that contains the SPs that the
  module will process.
- `voBlacklist`: Optional, an array of strings that contains VOs (COUs) for
  which the module will not generate entitlements.
- `defaultRoles`: Optional, an array of strings that contains the roles that all
  VOs must have.
- `tableNames`: Optional, an array of strings that contains the SQL tables that
  the module will retrieve user's VO membership information.
- `roleUrnNamespace`: Optional, a string containing the URN namespace of the
  entitlement.
- `roleAuthority`: Optional, a string containing the authority of the
  entitlement.
- `defaultIssuerDn`: Optional, a string containing the value that should be
  added if the certificate issuer is missing.
- `allowEmptyRole`: Optional, a boolean value that defines if will be created
  entitlements without role. Defaults to `false`.

### Example authproc filter configuration

```php
    authproc = [
        ...
        61 => [
            'class' => 'attrauthvoms:COmanageDbClientCertEntitlement',
            'userIdAttribute' => 'distinguishedName',
            'attributeName' => 'certEntitlement',
            'spWhitelist' => [
                'https://www.example1.org/sp',
                'https://www.example2.org/sp',
            ],
            'defaultRoles' => [
                'member',
                'vm_operator'
            ],
            'allowEmptyRole' => true,
            'voBlacklist' => [
                'vo.example01.org',
                'vo.example02.org',
            ],
            'role_urn_namespace' => 'urn:mace:example.org',
            'role_authority' => 'www.example.org',
            'defaultIssuerDn' => '',
        ],
```

## Compatibility matrix

This table matches the module version with the supported SimpleSAMLphp version.

| Module | SimpleSAMLphp |
| :----: | :-----------: |
|  v1.0  |     v1.14     |

## License

Licensed under the Apache 2.0 license, for details see `LICENSE`.
