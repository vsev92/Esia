<?php

class CryptoProSigner
{
    public function __construct(private string $cryptoproBin) {}
    public function sign(string $data, string $thumbprint): string
    {
        $tmpIn  = tempnam(sys_get_temp_dir(), 'esia_in_');
        $tmpOut = tempnam(sys_get_temp_dir(), 'esia_out_');

        file_put_contents($tmpIn, $data);

        $cmd = sprintf(
            '%s -sign -thumbprint "%s" -detached "%s" "%s"',
            escapeshellcmd($this->cryptoproBin),
            escapeshellarg($thumbprint),
            escapeshellarg($tmpIn),
            escapeshellarg($tmpOut)
        );

        exec($cmd, $output, $code);

        if ($code !== 0) {
            throw new CryptoProException('CryptoPro sign failed');
        }

        return file_get_contents($tmpOut);
    }
}
