<?php

use Vsev92\Esia\Config\EsiaConfig;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

class EsiaClient
{
    public function __construct(
        private  EsiaConfig $config,
        private  CryptoProSigner $signer = new CryptoProSigner('/opt/cprocsp/bin/amd64/cryptcp')
    ) {}

    /**
     * Формирует URL для авторизации в ESIA
     */
    public function getAuthorizationUrl(string $scope = 'openid'): string
    {
        $timestamp = gmdate('Y.m.d H:i:s O');
        $state = bin2hex(random_bytes(16));

        $dataToSign = implode('', [
            $this->config->clientId,
            $scope,
            $timestamp,
            $state,
        ]);

        $signature = $this->signer->sign($dataToSign, $this->config->certThumbprint);
        $signatureEncoded = base64_encode($signature);

        $query = http_build_query([
            'client_id' => $this->config->clientId,
            'scope' => $scope,
            'response_type' => 'code',
            'state' => $state,
            'timestamp' => $timestamp,
            'signature' => $signatureEncoded,
            'redirect_uri' => $this->config->redirectUri,
        ]);

        return $this->config->esiaBaseUrl . '/aas/oauth2/ac?' . $query;
    }

    /**
     * Получает access EsiaToken по коду авторизации
     */
    public function fetchEsiaToken(string $code): EsiaToken
    {
        $client = new Client([
            'base_uri' => $this->config->esiaBaseUrl,
            'timeout'  => 10,
        ]);

        $postData = [
            'client_id' => $this->config->clientId,
            'code' => $code,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->config->redirectUri,
        ];

        try {
            $response = $client->post('/aas/oauth2/te', [
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
                $data['access_EsiaToken'],
                $data['expires_in'],
                $data['refresh_EsiaToken'] ?? null
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
