<?php

namespace Vsev92\Esia\Esia;

use Vsev92\Esia\Config\EsiaConfig;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Vsev92\Esia\CryptoPro\CryptoProSigner;

class EsiaAuthClient
{
    public function __construct(
        private  EsiaConfig $config,
        private  CryptoProSigner $signer
    ) {
        $this->signer  = new CryptoProSigner('/opt/cprocsp/bin/amd64/cryptcp', $this->config->certThumbprint);
    }


    /**
     * Формирует URL для перенаправления пользователя в ЕСИА после запроса на аутентификацию через ЕСИА
     */
    public function getAuthorizationUrl(): string
    {
        $timestamp = gmdate('Y.m.d H:i:s O');
        $state = bin2hex(random_bytes(16)); //using for CSRF protection
        $redirectUri = $this->config->redirectUri;

        $clientSecret = implode('', [
            $this->config->clientId,
            $this->config->scope,
            $this->config->scopeOrg,
            $timestamp,
            $state,
            $redirectUri
        ]);

        $signature = $this->signer->getBase64UrlSafeSignature($clientSecret);

        $query = [
            'client_id' => $this->config->clientId,
            'scope' => $this->config->scope,
            'scope_org' => $this->config->scopeOrg,
            'response_type' => 'code',
            'state' => $state,
            'timestamp' => $timestamp,
            'signature' => $signature,
            'redirect_uri' => $redirectUri,
        ];

        return $this->config->esiaBaseUrl . '/v2/ac?' . http_build_query($query);
    }

    /**
     * Пользователь авторизуется в ЕСИА (логин, SMS, ЭЦП).
     * ЕСИА перенаправляет обратно на ваш redirectUri с кодом
     * https://yourapp.com/callback?code=AUTH_CODE&state=...
     * далее необходимо отправить AUTH_CODE POST запросом и получить токены
     */




    /**
     * Получает access EsiaAuthData по коду авторизации
     */
    public function fetchEsiaAuthData(string $code): EsiaAuthData  //Б.2.5
    {
        return $this->requestEsiaAuthData(
            grantType: 'authorization_code',
            code: $code
        );
    }

    /**
     * Обновляет истекший EsiaAuthData
     */
    public function refreshEsiaAuthData(EsiaAuthData $expired): EsiaAuthData  //Б.2.6
    {
        return $this->requestEsiaAuthData(
            grantType: 'refresh_token',
            refresh: $expired->getRefreshToken()
        );
    }

    private function requestEsiaAuthData(
        string $grantType,
        ?string $code = null,
        ?string $refresh = null
    ): EsiaAuthData {
        $httpClient = new Client([
            'base_uri' => $this->config->esiaBaseUrl,
            'timeout'  => 10,
        ]);

        $timestamp = gmdate('Y.m.d H:i:s O');
        $state = bin2hex(random_bytes(16));


        $clientSecret = [
            $this->config->clientId,
            $this->config->scope,
            $this->config->scopeOrg ?? '',
            $timestamp,
            $state,
            $this->config->redirectUri,
        ];

        if ($grantType === 'authorization_code') {
            $clientSecret[] = $code;
        }

        $clientSecretString = implode('', $clientSecret);

        $clientSecretEncoded = $this->signer->getBase64UrlSafeSignature($clientSecretString);

        $postData = [
            'client_secret' => $clientSecretEncoded,
            'client_id' => $this->config->clientId,
            'scope' => $this->config->scope,
            'scope_org' => $this->config->scopeOrg,
            'timestamp' => $timestamp,
            'state' => $state,
            'redirect_uri' => $this->config->redirectUri,
            'client_certificate_hash' => $this->config->client_certificate_hash,
            'grant_type' => $grantType,
            'token_type' => 'Bearer',
        ];

        if ($grantType === 'authorization_code') {
            $postData['code'] = $code;
        }

        if ($grantType === 'refresh_token') {
            $postData['refresh_token'] = $refresh;
        }

        try {
            $response = $httpClient->post('aas/oauth2/v3/te', [
                'form_params' => $postData,
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
            ]);

            $data = json_decode($response->getBody()->getContents(), true);

            if (isset($data['error'])) {
                throw new \RuntimeException('ESIA EsiaAuthData error: ' . $data['error']);
            }

            return new EsiaAuthData(
                $data['access_token'],
                $data['expires_in'],
                $data['token_type'],
                $data['refresh_token'] ?? null,
                $data['id_token'] ?? null
            );
        } catch (GuzzleException $e) {
            throw new \RuntimeException('HTTP request failed: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Получает данные пользователя по access EsiaAuthData
     */
    public function getPerson(EsiaAuthData $token): array
    {
        $client = new Client([
            'base_uri' => $this->config->esiaBaseUrl,
            'timeout'  => 10,
        ]);

        try {
            $response = $client->get('/rs/prns', [
                'headers' => [
                    'Authorization' => 'Bearer ' . $token->getAccessToken(),
                    'Accept' => 'application/json',
                ],
            ]);

            $data = json_decode($response->getBody()->getContents(), true);

            if (!is_array($data)) {
                throw new \RuntimeException('Invalid response from ESIA');
            }

            return $data;
        } catch (GuzzleException $e) {
            throw new \RuntimeException('HTTP request failed: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }
}
