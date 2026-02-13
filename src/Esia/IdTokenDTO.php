<?php

namespace Vsev92\Esia\Esia;

class IdTokenData
{
    public ?string $oid;
    public ?string $snils;
    public ?string $email;
    public ?string $firstName;
    public ?string $lastName;
    public ?string $middleName;
    public ?string $phone;

    public function __construct(public object $payload, public array $header, public string $signature)
    {
        $this->oid = $payload->sub ?? null;
        $this->snils = $payload->snils ?? null;
        $this->email = $payload->email ?? null;
        $this->firstName = $payload->given_name ?? null;
        $this->lastName = $payload->family_name ?? null;
        $this->middleName = $payload->middle_name ?? null;
        $this->phone = $payload->phone ?? null;
    }
}
