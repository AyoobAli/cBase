<?php

/**
 * Name: cBase
 * Description: A Class Base that has the main functions you need to build a class
 * Author: Ayoob Ali
 * Website: www.Ayoob.ae
 * License: GNU GPLv3
 * Version: v0.1.1 Beta
 * Date: 2022-02-28
 */

/**
    cBase is a PHP class that can be used as a base to any class, it
    provides the main functions needed to start with the new class. Simply
    make your class an extended class of cBase.
    Copyright (C) 2022  Ayoob Ali

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>
*/



class cBase {

    private $cBaseGlobalSettings = [
        "__htmlMSG"         => false,
        "__showError"       => false,
        "__showDebug"       => false,
        "__lastMsg"         => "",
        "__lastError"       => "",
        "__lastDebug"       => "",
        "__errorLevel"      => 6,
        "__debugLevel"      => 7,
        "__verbose"         => 1,
        "__resHeaders"      => [],

    ];


    public function __construct() {

        $className = get_called_class();
        $this->msg("$className class loaded", $this->getPrivateOptions('debugLevel'));
    }


    public function __destruct() {

        $className = get_called_class();
        $this->msg("$className class closed", $this->getPrivateOptions('debugLevel'));

    }


    // Clean String for Variable Names
    public function variableSafe ($string = "") {

        $clearString = trim(preg_replace("/[^A-Za-z0-9_-]/", '', $string));

        return $clearString;

    }


    // Clean String for HTML use
    public function htmlSafe ($string = "") {

        $clearString = htmlentities($string, ENT_QUOTES);
        return $clearString;

    }


    // Check if string starts with specific text
    public function startWith ($string = "", $start = "", $caseSensitive = true) {

        if ($caseSensitive == false) {
            $string = strtolower($string);
            $start = strtolower($start);
        }

        $string_len = strlen($string);
        $start_len = strlen($start);

        if ($string_len < $start_len || $string_len == 0 || $start_len == 0) {
            return false;
        }

        if (substr($string, 0, $start_len) === $start) {
            return true;
        }

        return false;

    }


    // Check if string Ends with specific text
    public function endWith ($string = "", $end = "", $caseSensitive = true) {

        if ($caseSensitive == false) {
            $string = strtolower($string);
            $end = strtolower($end);
        }

        $string_len = strlen($string);
        $end_len = strlen($end);

        if ($string_len < $end_len || $string_len == 0 || $end_len == 0) {
            return false;
        }

        if (substr($string, -$end_len) === $end) {
            return true;
        }

        return false;

    }


    // Check if string Contains specific text
    public function strContain ($string = "", $contain = "", $caseSensitive = true) {

        if ($caseSensitive == false) {
            $string = strtolower($string);
            $contain = strtolower($contain);
        }

        $string_len = strlen($string);
        $contain_len = strlen($contain);

        if ($string_len < $contain_len || $string_len == 0 || $contain_len == 0) {
            return false;
        }

        if (strpos($string, $contain) !== false){
            return true;
        }

        return false;

    }


    // Set cBase Global Settings value
    public function setGlobalSettings ($key = "", $value = "", $encrypt = "") {

        $key = $this->variableSafe($key);
        if ( $this->startWith($key, "__") ) {
            $this->msg("Key name can't start with (__)", $this->getPrivateOptions('errorLevel'));
            return false;
        }

        if (empty($key) || $key == null) {
            $this->msg("Key name can't be empty", $this->getPrivateOptions('errorLevel'));
            return false;
        }

        if ( ! empty($encrypt) && $encrypt != null ) {

            $this->msg("Encrypting Key ($key)", $this->getPrivateOptions('debugLevel'));

            if ( $encrypt == "__default" ) {
                $value = $this->encrypt($value);
            }else{
                $value = $this->encrypt($value, $encrypt);
            }

        }

        $this->cBaseGlobalSettings[$key] = $value;

        if ( $this->getGlobalSettings($key) == $value) {
            return true;
        }else{
            $this->msg("Can't save Key ($key)", $this->getPrivateOptions('errorLevel'));
            $this->msg("Save command was successful but key wasn't saved for unknown reason", $this->getPrivateOptions('debugLevel'));
            return false;
        }

        $this->msg("Some really weird issue is happening", $this->getPrivateOptions('debugLevel'));
        return false;

    }


    // Get cBase Global Settings value
    public function getGlobalSettings ($key = "", $decrypt = "") {

        $key = $this->variableSafe($key);
        if ( $this->startWith($key, "__") ) {
            $this->msg("Key name can't start with (__)", $this->getPrivateOptions('errorLevel'));
            return false;
        }

        if ( ! empty($key) && $key != null && isset($this->cBaseGlobalSettings[$key]) ) {

            $value = $this->cBaseGlobalSettings[$key];

            if ( ! empty($decrypt) && $decrypt != null ) {

                $this->msg("Decrypting Key ($key)", $this->getPrivateOptions('debugLevel'));
                if ( $decrypt == "__default" ) {
                    $value = $this->decrypt($value);
                }else{
                    $value = $this->decrypt($value, $decrypt);
                }

            }

            return $value;

        }

        $this->msg("Can't find Key ($key)", $this->getPrivateOptions('debugLevel'));
        return false;

    }


    // Set cBase Private Options value
    private function setPrivateOptions ($key = "", $value = "", $encrypt = "") {

        $key = $this->variableSafe($key);

        if ( ! $this->startWith($key, "__") ) {
            $key = "__" . $key;
        }

        if (empty($key) || $key == null) {
            $this->msg("Key name can't be empty", $this->getPrivateOptions('errorLevel'));
            return false;
        }

        if ( ! empty($encrypt) && $encrypt != null ) {

            $this->msg("Encrypting Key ($key)", $this->getPrivateOptions('debugLevel'));

            if ( $encrypt == "__default" ) {
                $value = $this->encrypt($value);
            }else{
                $value = $this->encrypt($value, $encrypt);
            }

        }

        $this->cBaseGlobalSettings[$key] = $value;

        if ( $this->getPrivateOptions($key) == $value) {
            return true;
        }else{
            $this->msg("Can't save Key ($key)", $this->getPrivateOptions('errorLevel'));
            $this->msg("Save command was successful but key wasn't saved for unknown reason", $this->getPrivateOptions('debugLevel'));
            return false;
        }

        $this->msg("Some really weird issue is happening", $this->getPrivateOptions('errorLevel'));
        return false;

    }


    // Get cBase Private Options value
    public function getPrivateOptions ($key = "", $decrypt = "") {

        $key = $this->variableSafe($key);

        if ( ! $this->startWith($key, "__") ) {
            $key = "__" . $key;
        }

        if ( ! empty($key) && $key != null && isset($this->cBaseGlobalSettings[$key]) ) {

            $value = $this->cBaseGlobalSettings[$key];

            if ( ! empty($decrypt) && $decrypt != null ) {

                $this->msg("Decrypting Key ($key)", $this->getPrivateOptions('debugLevel'));
                if ( $decrypt == "__default" ) {
                    $value = $this->decrypt($value);
                }else{
                    $value = $this->decrypt($value, $decrypt);
                }

            }

            return $value;

        }

        $this->msg("Can't find Key ($key)", $this->getPrivateOptions('errorLevel'));
        return false;

    }


    // Set cBase Verbose Level
    public function setVerbose ($level = 1) {

        $level = intval($level);
        $maxLevel = intval($this->getPrivateOptions("errorLevel")) - 1;
        if ( ! is_numeric($level) ) {
            $this->msg("Verbose must be equal to or more than (0)", $this->getPrivateOptions('errorLevel'));
            return false;
        }

        if ( $level < 0 ) {
            $level = 0;
        }elseif ( $level > $maxLevel ) {
            $level = $maxLevel;
        }

        if ( $this->setPrivateOptions('verbose', $level) ) {

            if ( $this->getPrivateOptions('verbose') == $level ) {
                $this->msg("Verbose level set to ($level)", $this->getPrivateOptions('debugLevel'));
                return true;
            }else{
                $this->msg("Can't set verbose level to ($level)", $this->getPrivateOptions('errorLevel'));
                return false;
            }

        }else{

            $this->msg("Can't set verbose level", $this->getPrivateOptions('errorLevel'));
            return false;

        }

        $this->msg("Some really weird issue is happening", $this->getPrivateOptions('debugLevel'));
        return false;

    }


    // Set cBase Show Error option
    public function setShowError ($showError = false) {

        $var = false;

        if ( is_bool($showError) && $showError === true ) {
            $var = true;
        }

        if ( is_numeric($showError) && $showError === 1 ) {
            $var = true;
        }

        if ( $this->setPrivateOptions('showError', $var) ) {

            if ( $this->getPrivateOptions('showError') == $var ) {
                $this->msg("Show Error option set to ($var)", $this->getPrivateOptions('debugLevel'));
                return true;
            }else{
                $this->msg("Can't set Show Error option to ($var)", $this->getPrivateOptions('errorLevel'));
                return false;
            }

        }else{

            $this->msg("Can't set Show Error option", $this->getPrivateOptions('errorLevel'));
            return false;

        }

        $this->msg("Some really weird issue is happening", $this->getPrivateOptions('debugLevel'));
        return false;

    }


    // Set cBase Show Debug option
    public function setShowDebug($showDebug = false) {

        $var = false;

        if ( (is_bool($showDebug) && $showDebug === true) || (is_numeric($showDebug) && $showDebug === 1) ) {
            $var = true;
        }

        if ( $this->setPrivateOptions('showDebug', $var) ) {

            if ( $this->getPrivateOptions('showDebug') == $var ) {
                $this->msg("Show Debug option set to ($var)", $this->getPrivateOptions('debugLevel'));
                return true;
            }else{
                $this->msg("Can't set Show Debug option to ($var)", $this->getPrivateOptions('errorLevel'));
                return false;
            }

        }else{

            $this->msg("Can't set Show Debug option", $this->getPrivateOptions('errorLevel'));
            return false;

        }

        $this->msg("Some really weird issue is happening", $this->getPrivateOptions('debugLevel'));
        return false;

    }


    // Return the last system Message
    public function getLastMsg () {
        return $this->getPrivateOptions('lastMsg');
    }


    // Return the last system Error Message
    public function getLastError () {
        return $this->getPrivateOptions('lastError');
    }



    // Return the last system Debug Message
    public function getLastDebug () {
        return $this->getPrivateOptions('lastDebug');
    }


    // Return the last system Debug Message
    public function getVerbose () {
        return $this->getPrivateOptions('verbose');
    }


    // Print System messages
    public function msg($string = "", $verbose = 1) {

        $verbose  = intval($verbose);


        $verboseLevel = $this->getPrivateOptions("verbose");
        $errorLevel = $this->getPrivateOptions("errorLevel");
        $debugLevel = $this->getPrivateOptions("debugLevel");

        if ( $this->getPrivateOptions("htmlMSG") ) {
            $string = $this->htmlSafe($string);
            $eolChar = "<br>\n";
        }else{
            $eolChar = "\n";
        }

        if ( $verboseLevel >= $verbose && $verboseLevel != 0 && $verbose > 0 && $verbose < $errorLevel) {

            $this->setPrivateOptions('lastMsg', $string);
            echo $eolChar . $string;

        }elseif ( $errorLevel === $verbose ) {

            $string = "Error: " . $string;
            $this->setPrivateOptions('lastError', $string);
            if ( $this->getPrivateOptions('showError') === true ) {
                echo $eolChar . $string;
            }

        }elseif ( $debugLevel === $verbose ) {

            $string = "Debug: " . $string;
            $this->setPrivateOptions('lastDebug', $string);
            if ( $this->getPrivateOptions('showDebug') === true ) {
                echo $eolChar . $string;
            }

        }

        return $string;

    }


    // Encrypt a String or Array
    public function encrypt($string = "", $key = 'vB5bbAkUp_#VK?Lj#L]78?Pgi]XnhzeV') {

        $keyVal = 'HxpHQ~82[APF+phya~>tZb[\D~N,te4D' . $key;

        if ( isset($this->cBaseGlobalSettings['encryption']) ) {
            $keyVal = $keyVal . $this->cBaseGlobalSettings['encryption'];
        }

        if ( is_array($string) === true ) {

            $c_encTxt = [];
            foreach ($string as $list_key => $list_value) {
                $c_encTxt[$list_key] = $this->encrypt($list_value, $key);
            }

        }else{

            $iv = openssl_random_pseudo_bytes(16);
            $c_text = openssl_encrypt($string, "AES-256-CBC", $keyVal, OPENSSL_RAW_DATA, $iv);
            $c_hash = hash_hmac('sha256', $c_text, $keyVal, true);
            $c_encTxt = base64_encode($iv . $c_hash . $c_text);

        }

        return $c_encTxt;

    }


    // Decrypt a String or Array
    public function decrypt($string = "", $key = 'vB5bbAkUp_#VK?Lj#L]78?Pgi]XnhzeV') {

        $keyVal = 'HxpHQ~82[APF+phya~>tZb[\D~N,te4D' . $key;

        if ( isset($this->cBaseGlobalSettings['encryption']) ) {
            $keyVal = $keyVal . $this->cBaseGlobalSettings['encryption'];
        }

        if ( is_array($string) === true ) {

            $c_decTxt = [];
            foreach ($string as $list_key => $list_value) {
                $c_decTxt[$list_key] = $this->decrypt($list_value, $key);
            }

        }else{

            $stringDecode = base64_decode($string);
            $iv = substr($stringDecode, 0, 16);
            $c_hash = substr($stringDecode, 16, 32);
            $c_text = substr($stringDecode, 48);

            if (hash_hmac('sha256', $c_text, $keyVal, true) !== $c_hash) {
                $this->msg("Wrong decryption key", $this->getPrivateOptions('debugLevel'));
                return $string;
            }

            $c_decTxt = openssl_decrypt($c_text, "AES-256-CBC", $keyVal, OPENSSL_RAW_DATA, $iv);

        }

        return $c_decTxt;
    }


    // Send Post requests
    public function postRequest($url = "", $body = "", $header = []) {

        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_HEADER, false);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $header);
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $body);

        $response['body'] = curl_exec($curl);
        $response['status'] = curl_getinfo($curl, CURLINFO_HTTP_CODE);

        curl_close($curl);

        return $response;

    }


    // Request URL
    public function requestURL($url = "", $method = "GET", $body = "", $header = [], $proxy = "", $proxyAuth = "") {

        $url = trim($url);
        $method = strtoupper(trim($method));

        if ( empty($url) || $url == null ) {
            $this->msg("-Invalid URL: $url", $this->getPrivateOptions('errorLevel'));
            return false;
        }

        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_URL, "$url");
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_FAILONERROR, true);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $header);

        if ( is_string($proxy) && !empty(trim($proxy)) ) {
            curl_setopt($curl, CURLOPT_PROXY, $proxy);
        }

        if ( is_string($proxyAuth) && !empty(trim($proxyAuth)) ) {
            curl_setopt($curl, CURLOPT_PROXYUSERPWD, $proxyAuth);
        }

        if ( $method === "POST" ) {
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        }else{
            curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "$method");
            curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        }

        curl_setopt($curl, CURLOPT_HEADERFUNCTION, function($curl, $resHeader) use (&$resHeaders) {

            $len = strlen($resHeader);
            $resHeader = explode(':', $resHeader, 2);

            if (count($resHeader) < 2) {
                return $len;
            }

            $resHeaders[strtolower(trim($resHeader[0]))][] = trim($resHeader[1]);
            $this->setPrivateOptions('resHeaders', $resHeaders);

            return $len;
        });

        $response['body'] = curl_exec($curl);
        $response['status'] = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $response['header'] = $this->getPrivateOptions('resHeaders');
        $this->setPrivateOptions('resHeaders', []);
        curl_close($curl);

        return $response;

    }


    // JSON String Validation
    public function validJson($json = '') {

        $json = trim($json);

        if ( empty($json) || $this->startWith($json, "{") === false ) {
            $this->msg("Invalid JSON string", $this->getPrivateOptions('errorLevel'));
            return false;
        }

        $jsonArray = json_decode($json, true);

        if (json_last_error() === JSON_ERROR_NONE) {
            return $jsonArray;
        }else{
            $this->msg("Can't decode JSON string", $this->getPrivateOptions('debugLevel'));
            return false;
        }

    }


    // Password Hashing
    public function passHash($password = "", $verify = "") {

        $salt = 't8-do^Ae862haAjiUiqB@g~ic-/CvF+a';
        $hashCost = 12;

        $password .= $salt;

        if ( isset($this->cBaseGlobalSettings['passwordSalt']) ) {
            $password = $this->cBaseGlobalSettings['passwordSalt'] . $password;
        }

        if ( empty($verify) ) {

            $passwordHash = password_hash($password, PASSWORD_BCRYPT, ["cost" => $hashCost]);
            $passwordEnc = $this->encrypt($passwordHash);
            return $passwordEnc;

        }else{

            $passwordDec = $this->decrypt($verify);
            return password_verify($password, $passwordDec);

        }

    }

}

?>