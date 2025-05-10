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
use ArtisanSdk\SRP;

class LuantiCentralAuthGlobalUser
{
    private int $id;
    private string $name;
    private string $password;

    public function __construct(int $id, string $name, string $password)
    {
        $this->id = $id;
        $this->name = $name;
        $this->password = $password;
    }

    public function getId(): int
    {
        return $this->id;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    // From decode_srp_verifier_and_salt
    private function decodeSrpVerifierAndSalt(string &$verifier, string &$salt): bool
    {
        $components = explode('#', $this->password);
        if (count($components) !== 4 || $components[1] !== '1') {
            return false;
        }

        $salt = base64_decode($components[2], true);
        $verifier = base64_decode($components[3], true);
        if ($salt === false || $verifier === false) {
            return false;
        }

        return true;
    }

    // From ModApiUtil::l_check_password_entry
    // srp_create_salted_verification_key
    public function checkPassword(string $password): bool
    {
        if (base64_encode(base64_decode($this->password, true)) === $this->password) {
            $slt = $this->name . $password;
            $digest = sha1($slt, true);
            $pwd = base64_encode($digest);
            return $pwd === $this->password;
        }

        $salt = ''; // bytes_s
        $verifier = '';
        if (!$this->decodeSrpVerifierAndSalt($verifier, $salt)) {
            return false;
        }

        // new_ng, 2048 bits
        $srp_ng_N = hex2bin(
            "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294" .
            "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D" .
            "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB" .
            "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74" .
            "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A" .
            "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D" .
            "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73" .
            "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" .
            "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F" .
            "9E4AFF73");
        $srp_ng_G = hex2bin("2");

        // calculate_x
        $x = hash('sha256', $this->name . ':' . $password, true);
        $gen_verifier = pow($srp_ng_G, $x) % $srp_ng_N;

        // $srp_client = new SRP\Client(new SRP\Config(
        //     "21766174458617435773191008891802753781907668374255538511144643224689886235383840957210909013086056401571399717235807266581649606472148410291413364152197364477180887395655483738115072677402235101762521901569820740293149529620419333266262073471054548368736039519702486226506248861060256971802984953561121442680157668000761429988222457090413873973970171927093992114751765168063614761119615476233422096442783117971236371647333871414335895773474667308967050807005509320424799678417036867928316761272274230314067548291133582479583061439577559347101961771406173684378522703483495337037655006751328447510550299250924469288819",
        //     "2",
        //     "5b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300",
        //     'sha256'
        // ));

        // $gen_verifier = hex2bin($srp_client->enroll($this->name, $password, bin2hex($salt)));

        return $verifier === $gen_verifier;
    }
}