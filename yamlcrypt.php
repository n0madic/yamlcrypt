#!/usr/bin/env php
<?php

$crypt_prefix = "CRYPT#";

if ($argc > 1) {
    $file = array_pop($argv);
    $encrypt = false;
    $password = getenv('YAML_PASSWORD');
    $dict_key = "secrets";
    for ($i = 1; $i < $argc-1; $i++) {
        switch ($argv[$i]) {
            case "-encrypt":
                $encrypt = true;
                break;
            case "-password":
                $i++;
                $password = $argv[$i];
                break;
            case "-key":
                $i++;
                $dict_key = $argv[$i];
                break;
        }
    }
} else {
    echo 'usage: yamlcrypt.php [-encrypt] [-key KEY] [-password SECRET] FILE

    Utility to encrypt/decrypt YAML values (decrypt by default)

    positional arguments:
      FILE              YAML file

    optional arguments:
      -encrypt          Encrypt values
      -key KEY          The key in YAML for encryption (default "secrets")
      -password SECRET  Password for encryption. NOT SAFE! It is better to use the
                        environment variable $YAML_PASSWORD
    ';
    exit(1);
}

if (!$password) {
    fwrite(STDERR, "ERROR: Password not specified!" . PHP_EOL);
    exit(2);
}
$password = md5($password, true);

$yml = yaml_parse_file($file);
foreach ($yml[$dict_key] as $key => $value) {
    if ($encrypt) {
        if (substr($value, 0, strlen($crypt_prefix)) != $crypt_prefix) {
            $yml[$dict_key][$key] = $crypt_prefix . AESEncrypt($value, $password);
        }
    } else {
        if (strpos($value, $crypt_prefix) === 0) {
            $value = substr($value, strlen($crypt_prefix));
        }
        $yml[$dict_key][$key] = AESDecrypt($value, $password);
    }
}
print_r(yaml_emit($yml, $encoding=YAML_UTF8_ENCODING));

function AESEncrypt($plaintext, $key) {
    $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
    $iv = openssl_random_pseudo_bytes($ivlen);
    $ciphertext_raw = openssl_encrypt($plaintext, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv.$ciphertext_raw);
}

function AESDecrypt($ciphertext, $key) {
    $c = base64_decode($ciphertext);
    $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
    $iv = substr($c, 0, $ivlen);
    $ciphertext_raw = substr($c, $ivlen);
    $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
    if ($original_plaintext === false) {
        fwrite(STDERR, "Error decryption! Verify the password is correct." . PHP_EOL);
        exit(3);
    }
    return $original_plaintext;
}
