<?php

return [
    'esia_base_url' => 'https://esia.gosuslugi.ru',
    'client_id' => 'YOUR_CLIENT_ID', //получают с госуслуг при регистрации юрлица
    'redirect_uri' => 'https://octula.ru/esia/auth-callback',

    // CryptoPro
    'cert_thumbprint' => 'AB12CD34...',
    'cryptopro_bin' => '/opt/cprocsp/bin/amd64/cryptcp',
];
