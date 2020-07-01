<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\OAuth\ResourceOwner;

use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;
use HWI\Bundle\OAuthBundle\Security\OAuthErrorHandler;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * AppleResourceOwner.
 *
 * @author Geoffrey Bachelet <geoffrey.bachelet@gmail.com>
 */
class AppleResourceOwner extends GenericOAuth2ResourceOwner
{

    /**
     * {@inheritdoc}
     */
    public function getUserInformation(array $accessToken, array $extraParameters = array())
    {
        $token = $accessToken['access_token'];

        $this->verifyToken($token);

        $data = self::jwt_decode($token);
        $data['id'] = $data['sub'];
        $response = $this->getUserResponse();
        $response->setPaths(['email' => 'email']);
        $response->setData($data);
        $response->setResourceOwner($this);
        $response->setOAuthToken(new OAuthToken($accessToken));
        return $response;
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken(Request $request, $redirectUri, array $extraParameters = array())
    {
        OAuthErrorHandler::handleOAuthError($request);

        $parameters = array_merge(array(
            'code' => $request->request->get('code'),
            'grant_type' => 'authorization_code',
            'client_id' => $this->options['client_id'],
            'client_secret' => $this->options['client_secret'],
            'redirect_uri' => $redirectUri,
        ), $extraParameters);

        $response = $this->doGetTokenRequest($this->options['access_token_url'], $parameters);
        $response = $this->getResponseContent($response);

        $this->validateResponseContent($response);

        $user = $request->request->get('user', []);
        if(!is_object($user))
            $user = json_decode($user, true);
        $data = self::jwt_decode($response['id_token']);
        $response['id'] = $data['sub'];
        $response['firstname'] = $user['name']['firstName'] ?? null;
        $response['lastname'] = $user['name']['lastName'] ?? null;
        $response['realname'] = ($user['name']['firstName'] ?? null).' '.($user['name']['lastName'] ?? null);
        $response['nickname'] = str_replace(' ', '.', ($user['name']['firstName'] ?? null).'.'.($user['name']['lastName'] ?? null));
        $response['name'] = str_replace(' ', '.', ($user['name']['firstName'] ?? null).'.'.($user['name']['lastName'] ?? null));
        $response['email'] = $user['email'] ?? null;

        return $response;
    }

    private static function jwt_decode($jwt)
    {
        $tks = explode('.', $jwt);
        list($headb64, $bodyb64, $cryptob64) = $tks;
        return json_decode(self::urlsafeB64Decode($bodyb64), true);
    }

    private static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * {@inheritdoc}
     */
    public function handles(Request $request)
    {
        return $request->request->has('code');
    }

    /**
     * {@inheritdoc}
     */
    protected function configureOptions(OptionsResolver $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults([
            'authorization_url' => 'https://appleid.apple.com/auth/authorize',
            'access_token_url' => 'https://appleid.apple.com/auth/token',
            'public_keys_url' => 'https://appleid.apple.com/auth/keys',
            'revoke_token_url' => '',
            'infos_url' => '',
            'use_commas_in_scope' => false,
            'display' => null,
            'type' => 'oauth2',
            'user_response_class' => 'HWI\Bundle\OAuthBundle\OAuth\Response\PathUserResponse',
            'scope' => 'name email',
            'appsecret_proof' => false,
            'paths' => [
                'email' => 'email'
            ]
        ]);
    }

    protected function verifyToken(string $token): void
    {
        $jwtToken = (new Parser())->parse((string) $token);
        $clientId = $this->options['client_id'];

        if (
            $jwtToken->isExpired() ||
            !$this->isSignatureValid($jwtToken) ||
            null === $jwtToken->getClaim('email') ||
            $clientId !== $jwtToken->getClaim('aud')
        ) {
            throw new BadCredentialsException();
        }
    }

    private function isSignatureValid(Token $token)
    {
        $publicKeyKid = $this->getPubKeyKid($token);
        $publicKeyString = $this->fetchPublicKey($publicKeyKid);

        $signer = new Sha256();
        $publicKey = new Key($publicKeyString['publicKey']);

        return $token->verify($signer, $publicKey);
    }

    private function getPubKeyKid($token)
    {
        $tks = explode('.', $token);
        list($headb64, $bodyb64, $cryptob64) = $tks;
        $head = json_decode(self::urlsafeB64Decode($headb64), true);

        return $head['kid'];
    }

    // copied https://github.com/GriffinLedingham/php-apple-signin/blob/master/ASDecoder.php#L58
    private function fetchPublicKey(string $publicKeyKid) : array
    {
        $reponsse = $this->httpRequest($this->options['public_keys_url'], null, [], 'GET');
        $decodedPublicKeys = $this->getResponseContent($reponsse);

        if(!isset($decodedPublicKeys['keys']) || count($decodedPublicKeys['keys']) < 1) {
            throw new Exception('Invalid key format.');
        }

        $kids = array_column($decodedPublicKeys['keys'], 'kid');
        $parsedKeyData = $decodedPublicKeys['keys'][array_search($publicKeyKid, $kids)];

        $parsedPublicKey= self::parseKey($parsedKeyData);
        $publicKeyDetails = openssl_pkey_get_details($parsedPublicKey);

        if(!isset($publicKeyDetails['key'])) {
            throw new Exception('Invalid public key details.');
        }

        return [
            'publicKey' => $publicKeyDetails['key'],
            'alg' => $parsedKeyData['alg']
        ];
    }

    private static function parseKey($source)
    {
        if (!is_array($source))
            $source = (array)$source;
        if (!empty($source) && isset($source['kty']) && isset($source['n']) && isset($source['e'])) {
            switch ($source['kty']) {
                case 'RSA':
                    if (array_key_exists('d', $source))
                        throw new UnexpectedValueException('Failed to parse JWK: RSA private key is not supported');

                    $pem = self::createPemFromModulusAndExponent($source['n'], $source['e']);
                    $pKey = openssl_pkey_get_public($pem);
                    if ($pKey !== false)
                        return $pKey;
                    break;
                default:
                    //Currently only RSA is supported
                    break;
            }
        }

        throw new UnexpectedValueException('Failed to parse JWK');
    }

    private static function createPemFromModulusAndExponent($n, $e)
    {
        $modulus = self::urlsafeB64Decode($n);
        $publicExponent = self::urlsafeB64Decode($e);


        $components = array(
            'modulus' => pack('Ca*a*', 2, self::encodeLength(strlen($modulus)), $modulus),
            'publicExponent' => pack('Ca*a*', 2, self::encodeLength(strlen($publicExponent)), $publicExponent)
        );

        $RSAPublicKey = pack(
            'Ca*a*a*',
            48,
            self::encodeLength(strlen($components['modulus']) + strlen($components['publicExponent'])),
            $components['modulus'],
            $components['publicExponent']
        );


        // sequence(oid(1.2.840.113549.1.1.1), null)) = rsaEncryption.
        $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
        $RSAPublicKey = chr(0) . $RSAPublicKey;
        $RSAPublicKey = chr(3) . self::encodeLength(strlen($RSAPublicKey)) . $RSAPublicKey;

        $RSAPublicKey = pack(
            'Ca*a*',
            48,
            self::encodeLength(strlen($rsaOID . $RSAPublicKey)),
            $rsaOID . $RSAPublicKey
        );

        $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
            chunk_split(base64_encode($RSAPublicKey), 64) .
            '-----END PUBLIC KEY-----';

        return $RSAPublicKey;
    }

    private static function encodeLength($length)
    {
        if ($length <= 0x7F) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }
}
