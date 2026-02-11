<?php

namespace Vsev92\Esia\Config;

use InvalidArgumentException;

class EsiaConfig
{
    public function __construct(
        public string $esiaBaseUrl,
        public string $clientId,
        public string $redirectUri,
        public string $certThumbprint,
        public string $cryptoProBin,
        public string $client_certificate_hash,
        public string $scope,
        public string $scopeOrg,
    ) {}


    public static function fromFile(string $path): self
    {
        if (!is_file($path)) {
            throw new InvalidArgumentException("ESIA config file not found: {$path}");
        }

        $config = require $path;

        if (!is_array($config)) {
            throw new InvalidArgumentException('ESIA config file must return array');
        }

        $validConfigKeys = [
            'esia_base_url',
            'client_id',
            'redirect_uri',
            'cert_thumbprint',
            'cryptopro_bin',
            'client_certificate_hash',
            'scope',
            'scopeOrg',
        ];

        foreach ($validConfigKeys as $key) {
            empty($config[$key]) && throw new InvalidArgumentException("Missing ESIA config key: {$key}");
        }

        return new self(
            esiaBaseUrl: $config['esia_base_url'],
            clientId: $config['client_id'],
            redirectUri: $config['redirect_uri'],
            certThumbprint: $config['cert_thumbprint'],
            cryptoProBin: $config['cryptopro_bin'],
            client_certificate_hash: $config['client_certificate_hash'],
            scope: $config['scope'],
            scopeOrg: $config['scopeOrg'],

        );
    }
}
