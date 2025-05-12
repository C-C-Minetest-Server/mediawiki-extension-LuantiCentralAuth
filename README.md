# Luanti CentralAuth Login for Mediawiki

This MediaWiki extension queries the [Luanti CentralAuth](https://content.luanti.org/packages/Emojiminetest/centralauth/) database (not to be confused with [MediaWiki's CentralAuth](https://www.mediawiki.org/wiki/Extension:CentralAuth)) for user authentication, ensuring a relationship between in-game and on-wiki accounts.

## Installation

Add the following into your `LocalSettings.php`:

```php
wfLoadExtension( 'LuantiCentralAuth' );

// Replace the 'xxxxx' with what your CentralAuth database uses.
// Note that the syntax is slightly different from Luanti Lua's pgmoon.
$wgLuantiCentralAuthDBConnection = 'host=xxxxx user=xxxxx password=xxxxx dbname=xxxxx';

// Set the following if you want to sync provileges from the game.

// The server ID of the syncing source.
$wgLuantiCentralAuthServerID = 'twi';

// A map of MediaWiki user groups to in-game privileges.
// A syntax similar to $wgAutopromote can be  used.
// Global privileges can be referred by <name>@global.
$wgLuantiCentralAuthPrivilegesMap = array(
        'ingame-server' => 'server',
        'ingame-ban' => 'ban',
        'ingame-role_helper' => 'role_helper',
);

// Usually you'd want these groups to be implicit
$wgImplicitGroups[] = 'ingame-server';
$wgImplicitGroups[] = 'ingame-ban';
$wgImplicitGroups[] = 'ingame-role_helper';
```

## Caution

1. If installing this extension on an existing wiki, it is possible that some in-game usernames may overlap with on-wiki usernames while their holder are not the same. This mod does not handle this; instead, rename the on-wiki account.
