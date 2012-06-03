<?php
/**
 * @package     Facebook
 * @author      Axel Etcheverry <axel@etcheverry.biz>
 * @copyright   Copyright (c) 2012 Axel Etcheverry (http://www.axel-etcheverry.com)
 * @license     http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace
 */
namespace Facebook\Api\Tests\Units;

require_once __DIR__ . '/../../../src/mageekguy.atoum.phar';
require_once __DIR__ . '/../../../src/Facebook/Api/Exception.php';
require_once __DIR__ . '/../../../src/Facebook/Api/Api.php';
require_once __DIR__ . '/../../../src/Facebook/Api/Client.php';

use mageekguy\atoum;
use mageekguy\atoum\asserter;
use mageekguy\atoum\asserters;
use Facebook;

class Client extends atoum\test
{
    const APP_ID = '117743971608120';
    const SECRET = '943716006e74d9b9283d4d5d8ab93204';

    const MIGRATED_APP_ID = '174236045938435';
    const MIGRATED_SECRET = '0073dce2d95c4a5c2922d1827ea0cca6';

    private static $kExpiredAccessToken                 = '206492729383450|2.N4RKywNPuHAey7CK56_wmg__.3600.1304560800.1-214707|6Q14AfpYi_XJB26aRQumouzJiGA';
    private static $kValidSignedRequest                 = '1sxR88U4SW9m6QnSxwCEw_CObqsllXhnpP5j2pxD97c.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyODEwNTI4MDAsIm9hdXRoX3Rva2VuIjoiMTE3NzQzOTcxNjA4MTIwfDIuVlNUUWpub3hYVVNYd1RzcDB1U2g5d19fLjg2NDAwLjEyODEwNTI4MDAtMTY3Nzg0NjM4NXx4NURORHBtcy1nMUM0dUJHQVYzSVdRX2pYV0kuIiwidXNlcl9pZCI6IjE2Nzc4NDYzODUifQ';
    private static $kNonTosedSignedRequest              = 'c0Ih6vYvauDwncv0n0pndr0hP0mvZaJPQDPt6Z43O0k.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiJ9';
    private static $kSignedRequestWithBogusSignature    = '1sxR32U4SW9m6QnSxwCEw_CObqsllXhnpP5j2pxD97c.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyODEwNTI4MDAsIm9hdXRoX3Rva2VuIjoiMTE3NzQzOTcxNjA4MTIwfDIuVlNUUWpub3hYVVNYd1RzcDB1U2g5d19fLjg2NDAwLjEyODEwNTI4MDAtMTY3Nzg0NjM4NXx4NURORHBtcy1nMUM0dUJHQVYzSVdRX2pYV0kuIiwidXNlcl9pZCI6IjE2Nzc4NDYzODUifQ';
    
    
    public function __construct(score $score = null, locale $locale = null, adapter $adapter = null)
    {
        $this->setTestNamespace('Tests\Units');
        parent::__construct($score, $locale, $adapter);
    }
    
    public function testConstructor()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $this->assert->object($facebook)
            ->isInstanceOf('\Facebook\Api\Api');
        
        $this->assert->string($facebook->getAppId())
            ->isEqualTo(self::APP_ID, 'Expect the App ID to be set.');
        
        $this->assert->string($facebook->getAppSecret())
            ->isEqualTo(self::SECRET, 'Expect the API secret to be set.');
    }
    
    public function testConstructorWithFileUpload()
    {
        $facebook = new TransientFacebook(array(
            'appId'      => self::APP_ID,
            'secret'     => self::SECRET,
            'fileUpload' => true
        ));
        
        $this->assert->string($facebook->getAppId())
            ->isEqualTo(self::APP_ID, 'Expect the App ID to be set.');
        
        $this->assert->string($facebook->getAppSecret())
            ->isEqualTo(self::SECRET, 'Expect the API secret to be set.');
        
        $this->assert->boolean($facebook->getFileUploadSupport())
            ->isTrue('Expect file upload support to be on.');
        
        // alias (depricated) for getFileUploadSupport -- test until removed
        $this->assert->boolean($facebook->useFileUploadSupport())
            ->isTrue('Expect file upload support to be on.');
    }
    
    public function testSetAppId()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $facebook->setAppId('dummy');
        
        $this->assert->string($facebook->getAppId())
            ->isEqualTo('dummy');
    }
    
    public function testSetAPPSecret()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $facebook->setAppSecret('dummy');
        
        $this->assert->string($facebook->getAppSecret())
            ->isEqualTo('dummy');
    }
    
    public function testSetAccessToken()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $facebook->setAccessToken('saltydog');
        
        $this->assert->string($facebook->getAccessToken())
            ->isEqualTo('saltydog');
    }
    
    public function testSetFileUploadSupport()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $this->assert->boolean($facebook->getFileUploadSupport())
            ->isFalse();
        
        // alias for getFileUploadSupport (depricated), testing until removed
        $this->assert->boolean($facebook->useFileUploadSupport())
            ->isFalse();

        $facebook->setFileUploadSupport(true);
        
        $this->assert->boolean($facebook->getFileUploadSupport())
            ->isTrue();
        
        // alias for getFileUploadSupport (depricated), testing until removed
        $this->assert->boolean($facebook->useFileUploadSupport())
            ->isTrue();
    }
    
    public function testGetCurrentURL()
    {
        $facebook = new FBGetCurrentURLFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        // fake the HPHP $_SERVER globals
        $_SERVER['HTTP_HOST']   = 'www.test.com';
        $_SERVER['REQUEST_URI'] = '/unit-tests.php?one=one&two=two&three=three';
        
        $current_url = $facebook->publicGetCurrentUrl();
        
        $this->assert->string($current_url)
            ->isEqualTo('http://www.test.com/unit-tests.php?one=one&two=two&three=three');
        
        // ensure structure of valueless GET params is retained (sometimes
        // an = sign was present, and sometimes it was not)
        // first test when equal signs are present
        $_SERVER['HTTP_HOST']   = 'www.test.com';
        $_SERVER['REQUEST_URI'] = '/unit-tests.php?one=&two=&three=';
        
        $current_url = $facebook->publicGetCurrentUrl();
        
        $this->assert->string($current_url)
            ->isEqualTo('http://www.test.com/unit-tests.php?one=&two=&three=');
        
        // now confirm that
        $_SERVER['HTTP_HOST']   = 'www.test.com';
        $_SERVER['REQUEST_URI'] = '/unit-tests.php?one&two&three';
        
        $current_url = $facebook->publicGetCurrentUrl();
        
        $this->assert->string($current_url)
            ->isEqualTo('http://www.test.com/unit-tests.php?one&two&three');

    }
    
    
    public function testGetLoginURL()
    {
        $facebook = new Facebook\Api\Client(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        // fake the HPHP $_SERVER globals
        $_SERVER['HTTP_HOST']   = 'www.test.com';
        $_SERVER['REQUEST_URI'] = '/unit-tests.php';
        
        $login_url = parse_url($facebook->getLoginUrl());
        
        $this->assert->string($login_url['scheme'])
            ->isEqualTo('https');
        
        $this->assert->string($login_url['host'])
            ->isEqualTo('www.facebook.com');
            
        $this->assert->string($login_url['path'])
            ->isEqualTo('/dialog/oauth');
            
        $expected_login_params = array(
            'client_id'     => self::APP_ID,
            'redirect_uri'  => 'http://www.test.com/unit-tests.php'
        );

        $query_map = array();
        parse_str($login_url['query'], $query_map);
        
        $this->assert->array($query_map)
            ->containsValues($expected_login_params)
            ->hasKey('state');
        
        // we don't know what the state is, but we know it's an md5 and should
        // be 32 characters long.
        $this->assert->integer((int)strlen($query_map['state']))
            ->isEqualTo(32);
    }
    
    public function testGetLoginURLWithExtraParams()
    {
        $facebook = new Facebook\Api\Client(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        // fake the HPHP $_SERVER globals
        $_SERVER['HTTP_HOST']   = 'www.test.com';
        $_SERVER['REQUEST_URI'] = '/unit-tests.php';
        
        $extra_params = array(
            'scope'     => 'email, sms',
            'nonsense'  => 'nonsense'
        );
        
        $login_url = parse_url($facebook->getLoginUrl($extra_params));
        
        $this->assert->string($login_url['scheme'])
            ->isEqualTo('https');
        
        $this->assert->string($login_url['host'])
            ->isEqualTo('www.facebook.com');
            
        $this->assert->string($login_url['path'])
            ->isEqualTo('/dialog/oauth');
        
        $expected_login_params = array_merge(array(
            'client_id'     => self::APP_ID,
            'redirect_uri'  => 'http://www.test.com/unit-tests.php'
        ), $extra_params);
        
        $query_map = array();
        parse_str($login_url['query'], $query_map);
        
        $this->assert->array($query_map)
            ->containsValues($expected_login_params)
            ->hasKey('state');
        
        // we don't know what the state is, but we know it's an md5 and should
        // be 32 characters long.
        $this->assert->integer((int)strlen($query_map['state']))
            ->isEqualTo(32);
    }
    
    
    public function testGetLoginURLWithScopeParamsAsArray()
    {
        $facebook = new Facebook\Api\Client(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        // fake the HPHP $_SERVER globals
        $_SERVER['HTTP_HOST']   = 'www.test.com';
        $_SERVER['REQUEST_URI'] = '/unit-tests.php';
        
        $scope_params_as_array = array(
            'email',
            'sms',
            'read_stream'
        );
        
        $extra_params = array(
            'scope'     => $scope_params_as_array,
            'nonsense'  => 'nonsense'
        );
        
        $login_url = parse_url($facebook->getLoginUrl($extra_params));
        
        $this->assert->string($login_url['scheme'])
            ->isEqualTo('https');
        
        $this->assert->string($login_url['host'])
            ->isEqualTo('www.facebook.com');
            
        $this->assert->string($login_url['path'])
            ->isEqualTo('/dialog/oauth');
        
        // expect api to flatten array params to comma separated list
        // should do the same here before asserting to make sure API is behaving
        // correctly;
        $extra_params['scope'] = implode(',', $scope_params_as_array);
        $expected_login_params = array_merge(array(
            'client_id' => self::APP_ID,
            'redirect_uri' => 'http://www.test.com/unit-tests.php'
        ), $extra_params);
        
        $query_map = array();
        parse_str($login_url['query'], $query_map);
        
        $this->assert->array($query_map)
            ->containsValues($expected_login_params)
            ->hasKey('state');
        
        // we don't know what the state is, but we know it's an md5 and should
        // be 32 characters long.
        $this->assert->integer((int)strlen($query_map['state']))
            ->isEqualTo(32);
    }
    
    public function testGetCodeWithValidCSRFState()
    {
        $facebook = new FBCode(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $facebook->setCSRFStateToken();
        
        $code = $_REQUEST['code'] = $this->generateMD5HashOfRandomValue();
        
        $_REQUEST['state'] = $facebook->getCSRFStateToken();
        
        $this->assert->string($facebook->publicGetCode())
            ->isEqualTo($code, 'Expect code to be pulled from $_REQUEST[\'code\']');
    }
    
    public function testGetCodeWithInvalidCSRFState()
    {
        $facebook = new FBCode(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $facebook->setCSRFStateToken();
        
        $code = $_REQUEST['code'] = $this->generateMD5HashOfRandomValue();
        
        $_REQUEST['state'] = $facebook->getCSRFStateToken() . 'forgery!!!';
        
        $this->assert->boolean($facebook->publicGetCode())
            ->isFalse('Expect getCode to fail, CSRF state should not match.');
    }
    
    public function testGetCodeWithMissingCSRFState()
    {
        $facebook = new FBCode(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $code = $_REQUEST['code'] = $this->generateMD5HashOfRandomValue();
        
        // intentionally don't set CSRF token at all
        $this->assert->boolean($facebook->publicGetCode())
            ->isFalse('Expect getCode to fail, CSRF state not sent back.');
    }
    
    public function testGetUserFromSignedRequest()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $_REQUEST['signed_request'] = self::$kValidSignedRequest;
        
        $this->assert->string($facebook->getUser())
            ->isEqualTo('1677846385', 'Failed to get user ID from a valid signed request.');
    }
    
    public function testGetSignedRequestFromCookie()
    {
        $facebook = new FBGetSignedRequestCookieFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $_COOKIE[$facebook->publicGetSignedRequestCookieName()] = self::$kValidSignedRequest;
        
        $this->assert->variable($facebook->publicGetSignedRequest())
            ->isNotNull();
        
        $this->assert->string($facebook->getUser())
            ->isEqualTo('1677846385', 'Failed to get user ID from a valid signed request.');
    }
    
    
    public function testGetSignedRequestWithIncorrectSignature()
    {
        $facebook = new FBGetSignedRequestCookieFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $_COOKIE[$facebook->publicGetSignedRequestCookieName()] = self::$kSignedRequestWithBogusSignature;
        
        $this->assert->variable($facebook->publicGetSignedRequest())
            ->isNull();
    }
    
    public function testNonUserAccessToken()
    {
        $facebook = new FBAccessToken(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        // no cookies, and no request params, so no user or code,
        // so no user access token (even with cookie support)
        $this->assert->string($facebook->publicGetApplicationAccessToken())
            ->isEqualTo($facebook->getAccessToken(), 'Access token should be that for logged out users.');
    }
    
    public function testAPIForLoggedOutUsers() 
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $response = $facebook->api(array(
            'method' => 'fql.query',
            'query' => 'SELECT name FROM user WHERE uid=4'
        ));
        
        $this->assert->integer(count($response))
            ->isEqualTo(1, 'Expect one row back.');
        
        $this->assert->string($response[0]['name'])
            ->isEqualTo('Mark Zuckerberg', 'Expect the name back.');
    }
    
    public function testAPIWithBogusAccessToken()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $facebook->setAccessToken('this-is-not-really-an-access-token');
        
        // if we don't set an access token and there's no way to
        // get one, then the FQL query below works beautifully, handing
        // over Zuck's public data.  But if you specify a bogus access
        // token as I have right here, then the FQL query should fail.
        // We could return just Zuck's public data, but that wouldn't
        // advertise the issue that the access token is at worst broken
        // and at best expired.
        try {
            $response = $facebook->api(array(
                'method' => 'fql.query',
                'query' => 'SELECT name FROM profile WHERE id=4',
            ));
          
            $this->fail('Should not get here.');
          
        } catch(\Facebook\Api\Exception $e) {
            $result = $e->getResult();
            
            $this->assert->boolean(is_array($result))
                ->isTrue('expect a result object');
                
            $this->assert->string($result['error_code'])
                ->isEqualTo('190', 'expect code');
        }
    }
    
    public function testAPIGraphPublicData()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $response = $facebook->api('/jerry');
        
        $this->assert->string($response['id'])
            ->isEqualTo('214707', 'should get expected id.');
    }
    
    public function testGraphAPIWithBogusAccessToken()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $facebook->setAccessToken('this-is-not-really-an-access-token');
        
        $this->assert->exception(function() use ($facebook) {
            $response = $facebook->api('/me');
        })
        ->isInstanceOf('\Facebook\Api\Exception')
        ->hasMessage('Invalid OAuth access token.', 'Expect the invalid OAuth token message.');
    }
    
    public function testGraphAPIWithExpiredAccessToken()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $facebook->setAccessToken(self::$kExpiredAccessToken);
        
        try {
            $response = $facebook->api('/me');
            $this->fail('Should not get here.');
        } catch(\Facebook\Api\Exception $e) {
            // means the server got the access token and didn't like it
            $error_msg_start = 'Error validating access token:';
            $this->assert->boolean(strpos((string) $e->getMessage(), $error_msg_start) === 0)
                ->isTrue('Expect the token validation error message.');
          
        }
    }
    
    public function testGraphAPIMethod()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $this->assert->exception(function() use ($facebook) {
            // naitik being bold about deleting his entire record....
            // let's hope this never actually passes.
            $response = $facebook->api('/naitik', $method = 'DELETE');
        })
        ->isInstanceOf('\Facebook\Api\Exception')
        ->hasMessage('(#200) User cannot access this application', 'Expect the invalid session message.');
    }
    
    public function testGraphAPIOAuthSpecError()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::MIGRATED_APP_ID,
            'secret' => self::MIGRATED_SECRET
        ));

        try {
            $response = $facebook->api('/me', array(
                'client_id' => self::MIGRATED_APP_ID
            ));

            $this->fail('Should not get here.');
            
        } catch(\Facebook\Api\Exception $e) {
            // means the server got the access token
            $msg = 'invalid_request: An active access token must be used '.
                'to query information about the current user.';
                
            $this->assert->string((string)$e)
                ->isEqualTo($msg, 'Expect the invalid session message.');
        }
    }
    
    public function testGraphAPIMethodOAuthSpecError() 
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::MIGRATED_APP_ID,
            'secret' => self::MIGRATED_SECRET
        ));

        try {
            $response = $facebook->api('/daaku.shah', 'DELETE', array(
                'client_id' => self::MIGRATED_APP_ID
            ));
            
            $this->fail('Should not get here.');
            
        } catch(\Facebook\Api\Exception $e) {
            $this->assert->integer(strpos($e, 'invalid_request'))
                ->isEqualTo(0);
        }
    }
    
    public function testCurlFailure()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        if (!defined('CURLOPT_TIMEOUT_MS')) {
            // can't test it if we don't have millisecond timeouts
            return;
        }

        $exception = null;
        
        try {
            // we dont expect facebook will ever return in 1ms
            Facebook\Api\Client::$CURL_OPTS[CURLOPT_TIMEOUT_MS] = 50;
            $facebook->api('/naitik');
        } catch(\Facebook\Api\Exception $e) {
            $exception = $e;
        }
        
        unset(Facebook\Api\Client::$CURL_OPTS[CURLOPT_TIMEOUT_MS]);
        
        if (!$exception) {
            $this->fail('no exception was thrown on timeout.');
        }

        $this->assert->integer($exception->getCode())
            ->isEqualTo(CURLE_OPERATION_TIMEOUTED, 'expect timeout');
        
        $this->assert->string($exception->getType())
            ->isEqualTo('CurlException', 'expect type');
    }
    
    public function testGraphAPIWithOnlyParams()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $response = $facebook->api('/jerry');
        
        $this->assert->array($response)
            ->hasKey('id', 'User ID should be public.')
            ->hasKey('name', 'User\'s name should be public.')
            ->hasKey('first_name', 'User\'s first name should be public.')
            ->hasKey('last_name', 'User\'s last name should be public.')
            ->notHasKey('work', 'User\'s work history should only be available with a valid access token.')
            ->notHasKey('education', 'User\'s education history should only be available with a valid access token.')
            ->notHasKey('verified', 'User\'s verification status should only be available with a valid access token.');
    }
    
    public function testLoginURLDefaults()
    {
        $_SERVER['HTTP_HOST']   = 'fbrell.com';
        $_SERVER['REQUEST_URI'] = '/examples';
        
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $encodedUrl = rawurlencode('http://fbrell.com/examples');
        
        $this->assert->variable(strpos($facebook->getLoginUrl(), $encodedUrl))
            ->isNotNull('Expect the current url to exist.');
    }
    
    public function testLoginURLDefaultsDropStateQueryParam()
    {
        $_SERVER['HTTP_HOST']   = 'fbrell.com';
        $_SERVER['REQUEST_URI'] = '/examples?state=xx42xx';
        
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $expectEncodedUrl = rawurlencode('http://fbrell.com/examples');
        
        $this->assert->boolean(strpos($facebook->getLoginUrl(), $expectEncodedUrl) > -1)
            ->isTrue('Expect the current url to exist.');
            
        $this->assert->boolean(strpos($facebook->getLoginUrl(), 'xx42xx'))
            ->isFalse('Expect the session param to be dropped.');
    }
    
    public function testLoginURLDefaultsDropCodeQueryParam()
    {
        $_SERVER['HTTP_HOST']   = 'fbrell.com';
        $_SERVER['REQUEST_URI'] = '/examples?code=xx42xx';
        
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $expectEncodedUrl = rawurlencode('http://fbrell.com/examples');
        
        $this->assert->boolean(strpos($facebook->getLoginUrl(), $expectEncodedUrl) > -1)
            ->isTrue('Expect the current url to exist.');
            
        $this->assert->boolean(strpos($facebook->getLoginUrl(), 'xx42xx'))
            ->isFalse('Expect the session param to be dropped.');
    }
    
    public function testLoginURLDefaultsDropSignedRequestParamButNotOthers()
    {
        $_SERVER['HTTP_HOST']   = 'fbrell.com';
        $_SERVER['REQUEST_URI'] = '/examples?signed_request=xx42xx&do_not_drop=xx43xx';
        
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $expectEncodedUrl = rawurlencode('http://fbrell.com/examples');
        
        $this->assert->boolean(strpos($facebook->getLoginUrl(), 'xx42xx'))
            ->isFalse('Expect the session param to be dropped.');
            
        $this->assert->boolean(strpos($facebook->getLoginUrl(), 'xx43xx') > -1)
            ->isTrue('Expect the do_not_drop param to exist.');
    }
    
    public function testLoginURLCustomNext()
    {
        $_SERVER['HTTP_HOST']   = 'fbrell.com';
        $_SERVER['REQUEST_URI'] = '/examples';
        
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $next = 'http://fbrell.com/custom';
        
        $loginUrl = $facebook->getLoginUrl(array(
            'redirect_uri'  => $next,
            'cancel_url'    => $next
        ));
        
        $currentEncodedUrl  = rawurlencode('http://fbrell.com/examples');
        $expectedEncodedUrl = rawurlencode($next);
        
        $this->assert->variable(strpos($loginUrl, $expectedEncodedUrl))
            ->isNotNull('Expect the custom url to exist.');
            
        $this->assert->boolean(strpos($loginUrl, $currentEncodedUrl))
            ->isFalse('Expect the current url to not exist.');
    }
    
    public function testLogoutURLDefaults()
    {
        $_SERVER['HTTP_HOST']   = 'fbrell.com';
        $_SERVER['REQUEST_URI'] = '/examples';
        
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $encodedUrl = rawurlencode('http://fbrell.com/examples');
        
        $this->assert->variable(strpos($facebook->getLogoutUrl(), $encodedUrl))
            ->isNotNull('Expect the current url to exist.');
    }
    
    public function testLoginStatusURLDefaults()
    {
        $_SERVER['HTTP_HOST']   = 'fbrell.com';
        $_SERVER['REQUEST_URI'] = '/examples';
        
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET,
        ));
        
        $encodedUrl = rawurlencode('http://fbrell.com/examples');
        
        $this->assert->variable(strpos($facebook->getLoginStatusUrl(), $encodedUrl))
            ->isNotNull('Expect the current url to exist.');
    }
    
    public function testLoginStatusURLCustom()
    {
        $_SERVER['HTTP_HOST']   = 'fbrell.com';
        $_SERVER['REQUEST_URI'] = '/examples';
        
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $encodedUrl1    = rawurlencode('http://fbrell.com/examples');
        $okUrl          = 'http://fbrell.com/here1';
        $encodedUrl2    = rawurlencode($okUrl);
        
        $loginStatusUrl = $facebook->getLoginStatusUrl(array(
            'ok_session' => $okUrl,
        ));
        
        $this->assert->variable(strpos($loginStatusUrl, $encodedUrl1))
            ->isNotNull('Expect the current url to exist.');
        
        $this->assert->variable(strpos($loginStatusUrl, $encodedUrl2))
            ->isNotNull('Expect the custom url to exist.');
    }
    
    public function testNonDefaultPort()
    {
        $_SERVER['HTTP_HOST']   = 'fbrell.com:8080';
        $_SERVER['REQUEST_URI'] = '/examples';
        
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $encodedUrl = rawurlencode('http://fbrell.com:8080/examples');
        
        $this->assert->variable(strpos($facebook->getLoginUrl(), $encodedUrl))
            ->isNotNull('Expect the current url to exist.');
    }
    
    public function testSecureCurrentUrl()
    {
        $_SERVER['HTTP_HOST']   = 'fbrell.com';
        $_SERVER['REQUEST_URI'] = '/examples';
        $_SERVER['HTTPS']       = 'on';
        
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $encodedUrl = rawurlencode('https://fbrell.com/examples');
        
        $this->assert->variable(strpos($facebook->getLoginUrl(), $encodedUrl))
            ->isNotNull('Expect the current url to exist.');
    }
    
    public function testSecureCurrentUrlWithNonDefaultPort()
    {
        $_SERVER['HTTP_HOST']   = 'fbrell.com:8080';
        $_SERVER['REQUEST_URI'] = '/examples';
        $_SERVER['HTTPS']       = 'on';
        
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $encodedUrl = rawurlencode('https://fbrell.com:8080/examples');
        
        $this->assert->variable(strpos($facebook->getLoginUrl(), $encodedUrl))
            ->isNotNull('Expect the current url to exist.');
    }
    
    public function testAppSecretCall()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $proper_exception_thrown = false;
        
        try {
            $response = $facebook->api('/' . self::APP_ID . '/insights');
            $this->fail('Desktop applications need a user token for insights.');
        } catch (\Facebook\Api\Exception $e) {
            //die($e->getMessage());
            $proper_exception_thrown = (strpos(
                $e->getMessage(), 
                'An access token is required to request this resource.'
            ) !== false);
        } catch (\Exception $e) {}

        $this->assert->boolean($proper_exception_thrown)
            ->isTrue(
                'Incorrect exception type thrown when trying to gain '.
                'insights for desktop app without a user access token.'
            );
    }
    
    public function testBase64UrlEncode()
    {
        $input  = 'Facebook rocks';
        $output = 'RmFjZWJvb2sgcm9ja3M';

        $this->assert->string(FBPublic::publicBase64UrlDecode($output))
            ->isEqualTo($input);
    }
    
    public function testSignedToken()
    {
        $facebook = new FBPublic(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $payload = $facebook->publicParseSignedRequest(self::$kValidSignedRequest);
        
        $this->assert->variable($payload)
            ->isNotNull('Expected token to parse');
        
        $this->assert->variable($facebook->getSignedRequest())
            ->isNull();
        
        $_REQUEST['signed_request'] = self::$kValidSignedRequest;
        
        $this->assert->array($facebook->getSignedRequest())
            ->isEqualTo($payload);
    }
    
    public function testNonTossedSignedtoken()
    {
        $facebook = new FBPublic(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));
        
        $payload = $facebook->publicParseSignedRequest(self::$kNonTosedSignedRequest);
        
        $this->assert->variable($payload)
            ->isNotNull('Expected token to parse');
        
        $this->assert->variable($facebook->getSignedRequest())
            ->isNull();

        $_REQUEST['signed_request'] = self::$kNonTosedSignedRequest;
        
        $this->assert->array($facebook->getSignedRequest())
            ->isEqualTo(array(
                'algorithm' => 'HMAC-SHA256'
            ));
    }
    
    public function testBundledCACert()
    {
        $facebook = new TransientFacebook(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        // use the bundled cert from the start
        Facebook\Api\Client::$CURL_OPTS[CURLOPT_CAINFO] = __DIR__ . '/../../../src/Facebook/Api/fb_ca_chain_bundle.crt';
        
        $response = $facebook->api('/naitik');

        unset(Facebook\Api\Client::$CURL_OPTS[CURLOPT_CAINFO]);
        
        $this->assert->string($response['id'])
            ->isEqualTo('5526183', 'should get expected id.');
    }
    
    public function testVideoUpload()
    {
        $facebook = new FBRecordURL(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $facebook->api(array(
            'method' => 'video.upload'
        ));
        
        $this->assert->string($facebook->getRequestedURL())
            ->match('#//api-video\.#', 'video.upload should go against api-video');
    }
    
    public function testGetUserAndAccessTokenFromSession()
    {
        $facebook = new PersistentFBPublic(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $facebook->publicSetPersistentData('access_token', self::$kExpiredAccessToken);
        $facebook->publicSetPersistentData('user_id', 12345);
        
        $this->assert->string($facebook->getAccessToken())
            ->isEqualTo(self::$kExpiredAccessToken, 'Get access token from persistent store.');
            
        $this->assert->integer($facebook->getUser())
            ->isEqualTo(12345, 'Get user id from persistent store.');
    }
    
    public function testGetUserAndAccessTokenFromSignedRequestNotSession()
    {
        $facebook = new PersistentFBPublic(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        $_REQUEST['signed_request'] = self::$kValidSignedRequest;
        
        $facebook->publicSetPersistentData('user_id', 41572);
        $facebook->publicSetPersistentData('access_token', self::$kExpiredAccessToken);
        
        $this->assert->string($facebook->getUser())
            ->isNotEqualTo('41572', 'Got user from session instead of signed request.');
        
        $this->assert->string($facebook->getUser())
            ->isEqualTo('1677846385', 'Failed to get correct user ID from signed request.');
            
        $this->assert->string($facebook->getAccessToken())
            ->isNotEqualTo(self::$kExpiredAccessToken, 'Got access token from session instead of signed request.');

        $this->assert->string($facebook->getAccessToken())
            ->isNotEmpty('Failed to extract an access token from the signed request.');
    }
    
    public function testGetUserWithoutCodeOrSignedRequestOrSession()
    {
        $facebook = new PersistentFBPublic(array(
            'appId'  => self::APP_ID,
            'secret' => self::SECRET
        ));

        // deliberately leave $_REQUEST and $_SESSION empty
        $this->assert->array($_REQUEST)
            ->isEmpty(
                'GET, POST, and COOKIE params exist even though '.
                'they should.  Test cannot succeed unless all of '.
                '$_REQUEST is empty.'
            );
        
        $this->assert->integer($facebook->getUser())
            ->isZero(
                'Got a user id, even without a signed request, '.
                'access token, or session variable.'
            );
        
        $this->assert->array($_SESSION)
            ->isEmpty(
                'Session superglobal incorrectly populated by getUser.'
            );
    }
    
    protected function generateMD5HashOfRandomValue()
    {
        return md5(uniqid(mt_rand(), true));
    }
    
    public function __destruct()
    {
        unset($_SERVER['HTTPS']);
        unset($_SERVER['HTTP_HOST']);
        unset($_SERVER['REQUEST_URI']);
        $_SESSION = array();
        $_COOKIE = array();
        $_REQUEST = array();
        $_POST = array();
        $_GET = array();
        if (session_id()) {
            session_destroy();
        }
    }
}



class TransientFacebook extends Facebook\Api\Api
{
    protected function setPersistentData($key, $value) {}
        
    protected function getPersistentData($key, $default = false)
    {
        return $default;
    }
    
    protected function clearPersistentData($key) {}
    
    protected function clearAllPersistentData() {}
}

class FBRecordURL extends TransientFacebook 
{
    private $url;

    protected function _oauthRequest($url, $params)
    {
        $this->url = $url;
    }

    public function getRequestedURL()
    {
        return $this->url;
    }
}

class FBPublic extends TransientFacebook 
{
    public static function publicBase64UrlDecode($input)
    {
        return self::base64UrlDecode($input);
    }

    public function publicParseSignedRequest($input)
    {
        return $this->parseSignedRequest($input);
    }
}

class PersistentFBPublic extends Facebook\Api\Client
{
    public function publicParseSignedRequest($input) 
    {
        return $this->parseSignedRequest($input);
    }

    public function publicSetPersistentData($key, $value)
    {
        $this->setPersistentData($key, $value);
    }
}

class FBCode extends Facebook\Api\Client
{
    public function publicGetCode() 
    {
        return $this->getCode();
    }

    public function setCSRFStateToken()
    {
        $this->establishCSRFTokenState();
    }

    public function getCSRFStateToken()
    {
        return $this->getPersistentData('state');
    }
}

class FBAccessToken extends TransientFacebook 
{
    public function publicGetApplicationAccessToken()
    {
        return $this->getApplicationAccessToken();
    }
}

class FBGetCurrentURLFacebook extends TransientFacebook 
{
    public function publicGetCurrentUrl()
    {
        return $this->getCurrentUrl();
    }
}

class FBGetSignedRequestCookieFacebook extends TransientFacebook 
{
    public function publicGetSignedRequest()
    {
        return $this->getSignedRequest();
    }

    public function publicGetSignedRequestCookieName()
    {
        return $this->getSignedRequestCookieName();
    }
}