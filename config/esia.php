<?php

return [
    'esia_base_url' => 'https://esia.gosuslugi.ru',
    'client_id' => 'YOUR_CLIENT_ID', //получают с госуслуг при регистрации юрлица
    'redirect_uri' => 'https://octula.ru/esia/auth-callback',

    // CryptoPro
    'cert_thumbprint' => 'AB12CD34...',
    'cryptopro_bin' => '/opt/cprocsp/bin/amd64/cryptcp',
    'client_certificate_hash' => '3A5F7C9D1E2F4B5A6C7D8E9F0A1B2C3D4E5F6A7B',
    /*Сертификат в формате X.509, который ИС использует для подписи данных через CryptoPro.
    Обычно устанавливается в хранилище «Личные» (MY) на сервере, где установлен CryptoPro.
    для вычисления хэша сертификата ЕСИА рекомендует использовать официальную утилиту (для Linux/Unix)
    https://esia.gosuslugi.ru/public/calc_cert_hash_unix.zip
    Пример работы утилиты
    ./calc_cert_hash_unix.sh /path/to/client_cert.cer*/
    'scope' => 'openid',
    'scopeOrg' => '',

];
