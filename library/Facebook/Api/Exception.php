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
namespace Facebook\Api;

/**
 * Thrown when an API call returns an exception.
 *
 * @author Naitik Shah <naitik@facebook.com>
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class Exception extends \Exception
{
    /**
     * The result from the API server that represents the exception information.
     */
    protected $_result;

    /**
     * Make a new API Exception with the given result.
     *
     * @param array $result The result from the API server
     */
    public function __construct($result) 
    {
        $this->_result = $result;

        $code = isset($result['error_code']) ? $result['error_code'] : 0;

        if (isset($result['error_description'])) {
            // OAuth 2.0 Draft 10 style
            $msg = $result['error_description'];
        } else if (isset($result['error']) && is_array($result['error'])) {
            // OAuth 2.0 Draft 00 style
            $msg = $result['error']['message'];
        } else if (isset($result['error_msg'])) {
            // Rest server style
            $msg = $result['error_msg'];
        } else {
            $msg = 'Unknown Error. Check getResult()';
        }

        parent::__construct($msg, $code);
    }

    /**
     * Return the associated result object returned by the API server.
     *
     * @return array The result from the API server
     */
    public function getResult() 
    {
        return $this->_result;
    }

    /**
     * Returns the associated type for the error. This will default to
     * 'Exception' when a type is not available.
     *
     * @return string
     */
    public function getType()
    {
        if (isset($this->_result['error'])) {
            
            $error = $this->_result['error'];
            
            if (is_string($error)) {
                // OAuth 2.0 Draft 10 style
                return $error;
            } else if (is_array($error)) {
                // OAuth 2.0 Draft 00 style
                if (isset($error['type'])) {
                    return $error['type'];
                }
            }
        }

        return 'Exception';
    }

    /**
     * To make debugging easier.
     *
     * @return string The string representation of the error
     */
    public function __toString() 
    {
        $str = $this->getType() . ': ';
        
        if ($this->code != 0) {
            $str .= $this->code . ': ';
        }
        
        return $str . $this->message;
    }
}