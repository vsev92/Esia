<?php

namespace Vsev92\Esia\CryptoPro;

class CryptoProSigner
{
    public function __construct(private string $cryptoproBinPath, private string $thumbprint) {}

    public function sign(string $data): string
    {
        $tmpIn  = tempnam(sys_get_temp_dir(), 'esia_in_');
        $tmpOut = tempnam(sys_get_temp_dir(), 'esia_out_');

        file_put_contents($tmpIn, $data);

        $cmd = sprintf(
            '%s -sign -thumbprint "%s" -detached "%s" "%s"',
            escapeshellcmd($this->cryptoproBinPath),
            escapeshellarg($this->thumbprint),
            escapeshellarg($tmpIn),
            escapeshellarg($tmpOut)
        );

        exec($cmd, $output, $code);

        if ($code !== 0) {
            throw new CryptoProException('CryptoPro sign failed');
        }
        $result = file_get_contents($tmpOut);
        unlink($tmpIn);
        unlink($tmpOut);
        return $result;
    }

    public function getBase64UrlSafeSignature(string $data): string
    {
        $signature = $this->sign($data);
        return rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
    }
}
