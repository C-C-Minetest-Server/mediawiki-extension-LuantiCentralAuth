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

use Mediawiki\Auth\AbstractPasswordPrimaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\PasswordAuthenticationRequest;
use MediaWiki\Auth\AuthManager;
use MediaWiki\User\UserRigorOptions;
use MediaWiki\User\User;

class LuantiCentralAuthPrimaryAuthenticationProvider extends AbstractPasswordPrimaryAuthenticationProvider
{
	private LuantiCentralAuthConnection $CAConnection;

	public function __construct(LuantiCentralAuthConnection $CAConnection, array $params = [])
	{
		parent::__construct($params);
		$this->CAConnection = $CAConnection;
	}

	private function isUsernameValid(string $username): bool
	{
		return
			preg_match("/[^a-zA-Z0-9-_]/i", $username) === 0
			|| strlen($username) <= 20;
	}

	public function beginPrimaryAuthentication(array $reqs)
	{
		$req = AuthenticationRequest::getRequestByClass($reqs, PasswordAuthenticationRequest::class);
		if (
			!$req
			|| $req->username === null
			|| $req->password === null
			|| !$this->isUsernameValid($req->username)
		) {
			return AuthenticationResponse::newAbstain();
		}

		$username = $req->username;
		$username = str_replace(' ', '_', $username);
		if ($username === false) {
			return $this->failResponse($req);
		}

		$globalUser = $this->CAConnection->getGlobalUser($username);
		if ($globalUser === null) {
			return $this->failResponse($req);
		}

		$password_given = $req->password;

		if ($globalUser->checkPassword($password_given)) {
			$username = $this->userNameUtils->getCanonical($globalUser->getName(), UserRigorOptions::RIGOR_USABLE);
			return AuthenticationResponse::newPass($username);
		}

		return $this->failResponse($req);
	}

	public function testUserCanAuthenticate($username)
	{
		return $this->testUserExists($username);
	}

	public function testUserExists($username, $flags = User::READ_NORMAL)
	{
		$globalUser = $this->CAConnection->getGlobalUser($username);
		return $globalUser !== null;
	}

	public function providerAllowsPropertyChange($property)
	{
		return false;
	}

	public function providerAllowsAuthenticationDataChange(AuthenticationRequest $req, $checkData = true)
	{
		return \StatusValue::newGood('ignored');
	}

	public function providerChangeAuthenticationData(AuthenticationRequest $req)
	{
		return;
	}

	public function accountCreationType()
	{
		return self::TYPE_LINK;
	}

	public function beginPrimaryAccountCreation($user, $creator, array $reqs)
	{
		return AuthenticationResponse::newAbstain();
	}

	public function getAuthenticationRequests($action, array $options)
	{
		switch ($action) {
			case AuthManager::ACTION_LOGIN:
				return [new PasswordAuthenticationRequest()];
			default:
				return [];
		}
	}
}
