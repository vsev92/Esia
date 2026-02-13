<?php


namespace Vsev92\Esia\Esia;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use phpseclib3\Math\BigInteger;
use phpseclib3\Crypt\RSA;
use RuntimeException;
use stdClass;

class IdTokenDecoder
{
    private string $jwksUrl = 'https://esia.gosuslugi.ru/jwks'; //json web key 

    public  function decode(string $idToken): stdClass
    {
        $header = $this->getHeader($idToken);
        $jwk = $this->getJwkByKeyId($header['kid'] ?? null);
        $publicKey = $this->convertJwkToPem($jwk);

        return JWT::decode($idToken, new Key($publicKey, 'RS256'));
    }

    private function getHeader(string $token): array
    {
        $header = explode('.', $token)[0];
        return $this->decodeBase64UrlJson($header);
    }

    private function getJwkByKeyId(?string $keyId): array
    {
        if (!$keyId) throw new RuntimeException('keyId not found');

        $jwks = json_decode(file_get_contents($this->jwksUrl), true);
        foreach ($jwks['keys'] ?? [] as $key) {
            $item = $key['kid'] ?? '';
            if ($item === $keyId) return $key;
        }
        throw new RuntimeException("JWK with kid $keyId not found");
    }

    private function convertJwkToPem(array $jwk): string
    {
        $modulus = $this->base64UrlDecode($jwk['n']);
        $exponent = $this->base64UrlDecode($jwk['e']);

        $n = new BigInteger($modulus, 256);
        $e = new BigInteger($exponent, 256);

        $publicKey = RSA::loadPublicKey([
            'n' => $n,
            'e' => $e
        ]);

        return $publicKey->toString('PKCS8');
    }

    private function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }

    private function decodeBase64UrlJson(string $data): array
    {
        return json_decode($this->base64UrlDecode($data), true);
    }
}
