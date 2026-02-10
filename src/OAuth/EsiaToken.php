<?php

final class EsiaToken
{
    public function __construct(
        public string $accessToken,
        public int $expiresIn,
        public ?string $refreshToken = null
    ) {}

    public function isExpired(): bool
    {
        return false;
    }
}
