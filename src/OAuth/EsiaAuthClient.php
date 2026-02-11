<?php

use Vsev92\Esia\Config\EsiaConfig;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

class EsiaAuthClient
{
    public function __construct(
        private  EsiaConfig $config,
        private  CryptoProSigner $signer = new CryptoProSigner('/opt/cprocsp/bin/amd64/cryptcp', $this->config->certThumbprint)
    ) {}


    /**
     * Формирует URL для перенаправления пользователя в ЕСИА после запроса на аутентификацию через ЕСИА
     */
    public function getAuthorizationUrl(string $scope = 'openid', ?string $scopeOrg = null): string
    {
        $timestamp = gmdate('Y.m.d H:i:s O');
        $state = bin2hex(random_bytes(16)); //using for CSRF protection
        $redirectUri = $this->config->redirectUri;

        $clientSecret = implode('', [
            $this->config->clientId,
            $scope,
            $scopeOrg ?? '',
            $timestamp,
            $state,
            $redirectUri
        ]);

        $signature = $this->signer->getBase64UrlSafeSignature($clientSecret);

        $query = [
            'client_id' => $this->config->clientId,
            'scope' => $scope,
            'scope_org' => $scopeOrg,
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
     * Получает access EsiaToken по коду авторизации
     */
    public function fetchEsiaToken(string $code, string $scope, ?string $scopeOrg = null, ?string $codeVerifier = null): EsiaToken
    {
        $client = new Client([
            'base_uri' => $this->config->esiaBaseUrl,
            'timeout'  => 10,
        ]);

        // 1. Генерация timestamp и state для запроса
        $timestamp = gmdate('Y.m.d H:i:s O');
        $state = bin2hex(random_bytes(16));

        // 2. Формируем строку для подписи (client_secret)
        $dataToSign = implode('', [
            $this->config->clientId,
            $scope,
            $scopeOrg ?? '',
            $timestamp,
            $state,
            $this->config->redirectUri,
            $code,
        ]);

        // 3. Подписываем ГОСТ Р 34.10-2012
        $signature = $this->signer->sign($dataToSign, $this->config->certThumbprint);

        // 4. Кодируем в base64 url safe
        $clientSecretEncoded = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');

        // 5. Формируем POST данные
        $postData = [
            'client_id' => $this->config->clientId,
            'scope' => $scope,
            'scope_org' => $scopeOrg,
            'timestamp' => $timestamp,
            'state' => $state,
            'redirect_uri' => $this->config->redirectUri,
            'client_secret' => $clientSecretEncoded,
            'code' => $code,
            'grant_type' => 'authorization_code',
            'token_type' => 'Bearer',
        ];

        if ($codeVerifier) {
            $postData['code_verifier'] = $codeVerifier; // для PKCE
        }

        try {
            $response = $client->post('aas/oauth2/v3/te', [
                'form_params' => $postData,
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
            ]);

            $data = json_decode($response->getBody()->getContents(), true);

            if (isset($data['error'])) {
                throw new \RuntimeException('ESIA EsiaToken error: ' . $data['error']);
            }

            return new EsiaToken(
                $data['access_token'],
                $data['expires_in'],
                $data['refresh_token'] ?? null
            );
        } catch (GuzzleException $e) {
            throw new \RuntimeException('HTTP request failed: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Получает данные пользователя по access EsiaToken
     */
    public function getPerson(string $accessEsiaToken): array
    {
        $client = new Client([
            'base_uri' => $this->config->esiaBaseUrl,
            'timeout'  => 10,
        ]);

        try {
            $response = $client->get('/rs/prns', [
                'headers' => [
                    'Authorization' => 'Bearer ' . $accessEsiaToken,
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
