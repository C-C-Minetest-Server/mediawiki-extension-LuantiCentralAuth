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
 */

namespace MediaWiki\Extension\LuantiCentralAuth;

use MediaWiki\MediaWikiServices;

/** @phpcs-require-sorted-array */
return [
    'LuantiCentralAuth.LuantiCentralAuthConnection' => function (MediaWikiServices $services): LuantiCentralAuthConnection {
        $connectionParam = $services->getMainConfig()->get('LuantiCentralAuthDBConnection');
        return new LuantiCentralAuthConnection(
            $connectionParam,
        );
    },
];