<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\Tests\OAuth\ResourceOwner;

use HWI\Bundle\OAuthBundle\OAuth\ResourceOwner\AppleResourceOwner;
use HWI\Bundle\OAuthBundle\Tests\Fixtures\CustomUserResponse;
use Symfony\Component\HttpFoundation\Request;

class AppleResourceOwnerTest extends GenericOAuth2ResourceOwnerTest
{
    protected $resourceOwnerClass = AppleResourceOwner::class;
    protected $userResponse = <<<json
{
    "sub": "1",
    "name": {
        "firstName": "foo",
        "lastName": "bar",
        "email": "foo@example.com"
    }
}
json;

    protected $paths = [
        'identifier' => 'id',
        'firstname' => 'name.firstName',
        'lastname' => 'name.lastName',
        'realname' => ['name.firstName', 'name.lastName'],
        'email' => 'name.email',
    ];

    protected $expectedUrls = [
        'authorization_url' => 'http://user.auth/?test=2&response_type=code&client_id=clientid&scope=name+email&redirect_uri=http%3A%2F%2Fredirect.to%2F',
        'authorization_url_csrf' => 'http://user.auth/?test=2&response_type=code&client_id=clientid&scope=name+email&state=random&redirect_uri=http%3A%2F%2Fredirect.to%2F',
    ];

    public function testHandleRequest()
    {
        $request = new Request(['test' => 'test']);

        $this->assertFalse($this->resourceOwner->handles($request));

        $request = new Request(['code' => 'test']);

        $this->assertFalse($this->resourceOwner->handles($request));

        $request = new Request([], ['code' => 'test']);

        $this->assertTrue($this->resourceOwner->handles($request));

        $request = new Request([], ['code' => 'test', 'test' => 'test']);

        $this->assertTrue($this->resourceOwner->handles($request));
    }

    public function testGetAccessTokenFailedResponse()
    {
        $this->expectException(\Symfony\Component\Security\Core\Exception\AuthenticationException::class);

        $this->mockHttpClient('{"error": {"message": "invalid"}}', 'application/json; charset=utf-8');
        $request = new Request(['code' => 'code']);

        $this->resourceOwner->getAccessToken($request, 'http://redirect.to/');
    }

    public function testDisplayPopup()
    {
        $resourceOwner = $this->createResourceOwner($this->resourceOwnerName, ['display' => 'popup']);

        $this->assertEquals(
            $this->options['authorization_url'].'&response_type=code&client_id=clientid&scope=name+email&state=random&redirect_uri=http%3A%2F%2Fredirect.to%2F',
            $resourceOwner->getAuthorizationUrl('http://redirect.to/')
        );
    }

    public function testRevokeToken()
    {
        $this->httpResponseHttpCode = 200;
        $this->mockHttpClient('{"access_token": "bar"}', 'application/json');

        $this->assertTrue($this->resourceOwner->revokeToken('token'));
    }

    public function testRevokeTokenFails()
    {
        $this->httpResponseHttpCode = 401;
        $this->mockHttpClient('{"access_token": "bar"}', 'application/json');

        $this->assertFalse($this->resourceOwner->revokeToken('token'));
    }

    public function testGetAccessTokenErrorResponse()
    {
        $this->expectException(\Symfony\Component\Security\Core\Exception\AuthenticationException::class);

        $this->mockHttpClient();

        $request = new Request([
            'error_code' => 901,
            'error_message' => 'This app is in sandbox mode.  Edit the app configuration at http://developers.facebook.com/apps to make the app publicly visible.',
        ]);

        $this->resourceOwner->getAccessToken($request, 'http://redirect.to/');
    }

    public function testCustomResponseClass()
    {
        $class = CustomUserResponse::class;
        $resourceOwner = $this->createResourceOwner('oauth2', ['user_response_class' => $class]);

        $this->mockHttpClient();

        /** @var CustomUserResponse $userResponse */
        $userResponse = $resourceOwner->getUserInformation(['access_token' => 'token', 'uid' => '1']);

        $this->assertInstanceOf($class, $userResponse);
        $this->assertEquals('foo666', $userResponse->getUsername());
        $this->assertEquals('foo', $userResponse->getNickname());
        $this->assertEquals('token', $userResponse->getAccessToken());
        $this->assertNull($userResponse->getRefreshToken());
        $this->assertNull($userResponse->getExpiresIn());
    }

}
