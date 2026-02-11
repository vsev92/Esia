<?php

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

final class HttpClient
{
    public function __construct(
        private readonly Client $client
    ) {}

    public function get(string $url, array $headers = []): array
    {
        try {
            $response = $this->client->get($url, ['headers' => $headers]);
            return json_decode($response->getBody()->getContents(), true);
        } catch (GuzzleException $e) {
            throw new \RuntimeException('HTTP GET failed: ' . $e->getMessage());
        }
    }

    public function post(string $url, array $data = [], array $headers = []): array
    {
        try {
            $response = $this->client->post($url, [
                'form_params' => $data,
                'headers' => $headers,
            ]);
            return json_decode($response->getBody()->getContents(), true);
        } catch (GuzzleException $e) {
            throw new \RuntimeException('HTTP POST failed: ' . $e->getMessage());
        }
    }
}
