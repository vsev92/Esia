<?php

namespace Vsev92\Esia\Esia;

use Carbon\Carbon;
use stdClass;

class EsiaAuthData
{
    private string $accessToken;
    private string $idToken;
    private int $expiresIn;
    private string $tokenType;
    private ?string $refreshToken;
    private string $oid;
    private stdClass $idTokenPayload;
    private Carbon $createdAt;

    public function __construct(
        string $accessToken,
        string $idToken,
        int $expiresIn,
        string $tokenType,
        ?string $refreshToken = null,
        ?Carbon $createdAt = null
    ) {
        $this->accessToken = trim($accessToken);
        $this->idToken = trim($idToken);
        $this->decodeIdToken($this->idToken);
        $this->expiresIn = $expiresIn;
        $this->tokenType = $tokenType;
        $this->refreshToken = $refreshToken;
        $this->createdAt = $createdAt ?? Carbon::now();
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function getIdToken(): string
    {
        return $this->idToken;
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

    private function decodeIdToken(string $token)
    {
        $decoder = new IdTokenDecoder();
        $this->idTokenPayload =  $decoder->decode($token);
        $this->oid = $this->idTokenPayload->sub;
    }
}
