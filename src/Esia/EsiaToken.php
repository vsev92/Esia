<?php

use Carbon\Carbon;

class EsiaToken
{
    private string $accessToken;
    private int $expiresIn;
    private string $tokenType;
    private ?string $refreshToken;
    private Carbon $createdAt;

    public function __construct(
        string $accessToken,
        int $expiresIn,
        string $tokenType,
        ?string $refreshToken = null,
        ?Carbon $createdAt = null
    ) {
        $this->accessToken = trim($accessToken);
        $this->expiresIn = $expiresIn;
        $this->tokenType = $tokenType;
        $this->refreshToken = $refreshToken;
        $this->createdAt = $createdAt ?? Carbon::now();
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function getExpiresIn(): int
    {
        return $this->expiresIn;
    }

    public function getTokenType(): string
    {
        return $this->tokenType;
    }

    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    public function getCreatedAt(): Carbon
    {
        return $this->createdAt;
    }

    public function isExpired(): bool
    {
        return $this->createdAt->copy()->addSeconds($this->expiresIn)->isPast();
    }
}
