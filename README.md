Facebook PHP5.3+ SDK (v.3.1.1)
==========================

[![Build Status](https://secure.travis-ci.org/euskadi31/Facebook.png?branch=master)](http://travis-ci.org/euskadi31/Facebook)

The [Facebook Platform](http://developers.facebook.com/) is
a set of APIs that make your app more social

This repository contains the open source PHP5.3+ SDK that allows you to access Facebook Platform from your PHP app. Except as otherwise noted, the Facebook PHP SDK
is licensed under the Apache Licence, Version 2.0
(http://www.apache.org/licenses/LICENSE-2.0.html)

Install
-------

Use [Composer.phar](http://getcomposer.org/)

    cd Facebook/
    curl -s https://getcomposer.org/installer | php
    php composer.phar install

Usage
-----

The examples are a good place to start. The minimal you'll need to
have is:

    namespace YourAppNamespace;
    
    require __DIR__ . '/vendor/autoload.php';
    
    use Facebook;
    
    $facebook = new Facebook\Api\Client(array(
        'appId'  => 'YOUR_APP_ID',
        'secret' => 'YOUR_APP_SECRET',
    ));

    // Get User ID
    $user = $facebook->getUser();

To make [API][API] calls:

    if ($user) {
        try {
            // Proceed knowing you have a logged in user who's authenticated.
            $user_profile = $facebook->api('/me');
        } catch (Facebook\Api\Exception $e) {
            error_log($e);
            $user = null;
        }
    }

Login or logout url will be needed depending on current user state.

    if ($user) {
        $logoutUrl = $facebook->getLogoutUrl();
    } else {
        $loginUrl = $facebook->getLoginUrl();
    }

[API]: http://developers.facebook.com/docs/api


Tests
-----

In order to keep us nimble and allow us to bring you new functionality, without
compromising on stability, we have ensured full test coverage of the SDK.
We are including this in the open source repository to assure you of our
commitment to quality, but also with the hopes that you will contribute back to
help keep it stable. The easiest way to do so is to file bugs and include a
test case.

The tests can be executed by using this command from the base directory:

    php -f Tests/Units/Api/Client.php
    
Report Issues/Bugs
===============
[Bugs](https://github.com/euskadi31/Facebook/issues)

[Questions](http://facebook.stackoverflow.com)
