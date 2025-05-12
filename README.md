# Luanti CentralAuth Login for Mediawiki

This MediaWiki extension queries the [Luanti CentralAuth](https://content.luanti.org/packages/Emojiminetest/centralauth/) database (not to be confused with [MediaWiki's CentralAuth](https://www.mediawiki.org/wiki/Extension:CentralAuth)) for user authentication, ensuring a relationship between in-game and on-wiki accounts.

## Installation

Add the following into your `LocalSettings.php`:

```php
wfLoadExtension( 'LuantiCentralAuth' );

// Replace the 'xxxxx' with what your CentralAuth database uses.
$wgLuantiCentralAuthDBConnection = 'host=xxxxx user=xxxxx password=xxxxx dbname=xxxxx';
$wgAuthManagerAutoConfig['primaryauth'][\MediaWiki\Extension\LuantiCentralAuth\LuantiCentralAuthPrimaryAuthenticationProvider::class] = [
    'class' => \MediaWiki\Extension\LuantiCentralAuth\LuantiCentralAuthPrimaryAuthenticationProvider::class,
    'services' => [
        'LuantiCentralAuth.LuantiCentralAuthConnection',
    ],
    'args' => [ [
        'authoritative' => true,
    ] ],
    'sort' => 50,
];
```

## Caution

1. If installing this extension on an existing wiki, it is possible that some in-game usernames may overlap with on-wiki usernames while their holder are not the same. This mod does not handle this; instead, rename the on-wiki account.
