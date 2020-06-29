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
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\OptionsResolver\OptionsResolver;

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
        $data = self::jwt_decode($accessToken['access_token']);
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


        $ch = curl_init();
        curl_setopt_array ($ch, [
            CURLOPT_URL => 'https://appleid.apple.com/auth/token',
            CURLOPT_POSTFIELDS => http_build_query($parameters),
            CURLOPT_RETURNTRANSFER => true
        ]);
        $response = curl_exec($ch);
        $response = json_decode($response, true);

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
}
