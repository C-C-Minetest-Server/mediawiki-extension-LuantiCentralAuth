<?php
/**
 * This program is a free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @file
 * @ingroup Auth
 */

namespace MediaWiki\Extension\LuantiCentralAuth;

use MediaWiki\Config\Config;
use MediaWiki\User\User;

class LuantiCentralAuthHooks
{
    private LuantiCentralAuthConnection $CAConnection;
    private Config $config;

    public function __construct(
        LuantiCentralAuthConnection $CAConnection,
        Config $config
    ) {
        $this->CAConnection = $CAConnection;
        $this->config = $config;
    }

    private static function parseCondition(array $privs, string|array $condition)
    {
        if (is_string($condition)) {
            return in_array($condition, $privs);
        }

        switch ($condition[0]) {
            case '&': // AND
                for ($i = 1; $i < count($condition); $i++) {
                    if (!LuantiCentralAuthHooks::parseCondition($privs, $condition[$i])) {
                        return false;
                    }
                }
                return true;
            case '|': // OR
                for ($i = 1; $i < count($condition); $i++) {
                    if (LuantiCentralAuthHooks::parseCondition($privs, $condition[$i])) {
                        return true;
                    }
                }
                return false;
            case '!': // NOT
                for ($i = 1; $i < count($condition); $i++) {
                    if (LuantiCentralAuthHooks::parseCondition($privs, $condition[$i])) {
                        return false;
                    }
                }
                return true;
            case '^': // XOR
                $result = false;
                for ($i = 1; $i < count($condition); $i++) {
                    if (LuantiCentralAuthHooks::parseCondition($privs, $condition[$i])) {
                        if ($result) {
                            return false;
                        }
                        $result = true;
                    }
                }
                return $result;
        }
        return false;
    }

    public function onUserEffectiveGroups(User &$user, array &$aUserGroups)
    {
        $name = $user->getName();
        $serverID = $this->config->get('LuantiCentralAuthServerID');
        if ($serverID === '')
            return;
        $privilegesMap = $this->config->get('LuantiCentralAuthPrivilegesMap');

        $globalPrivileges = $this->CAConnection->getGlobalUserPrivs($name);
        $localPrivileges = $this->CAConnection->getLocalUserPrivs($serverID, $name);

        $privileges = array();
        foreach ($globalPrivileges as $privilege) {
            $privileges[] = $privilege . '@global';
        }
        foreach ($localPrivileges as $privilege) {
            $privileges[] = $privilege;
        }

        foreach ($privilegesMap as $group => $condition) {
            if (
                LuantiCentralAuthHooks::parseCondition($privileges, $condition)
                && !in_array($group, $aUserGroups)
            ) {
                $aUserGroups[] = $group;
            }
        }
    }
}