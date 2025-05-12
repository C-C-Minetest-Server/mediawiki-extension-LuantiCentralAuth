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

class LuantiCentralAuthConnection
{
    private \PgSql\Connection $postgresConnection;

    public function __construct(string $connectionParam)
    {
        if ($postgresConnection = \pg_connect($connectionParam)) {
            $this->postgresConnection = $postgresConnection;
        } else {
            throw new \Exception('Could not connect to PostgreSQL database');
        }
    }

    public function getGlobalUser(string $username): ?LuantiCentralAuthGlobalUser
    {
        $query = \pg_query_params(
            $this->postgresConnection,
            'SELECT gu_id, gu_name, gu_password FROM global_user WHERE lower(gu_name) = lower($1)',
            [$username]
        );
        if ($query === false) {
            throw new \Exception('Query failed: ' . \pg_last_error($this->postgresConnection));
        }

        $row = \pg_fetch_assoc($query);
        if ($row === false) {
            return null;
        }

        return new LuantiCentralAuthGlobalUser(
            $row['gu_id'],
            $row['gu_name'],
            $row['gu_password']
        );
    }
}