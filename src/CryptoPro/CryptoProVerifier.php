<?php

namespace Vsev92\Esia\CryptoPro;

class CryptoProVerifier
{
    public function verify(string $data, string $signature, string $thumbprint): bool
    {
        $tmpData = tempnam(sys_get_temp_dir(), 'esia_data_');
        $tmpSign = tempnam(sys_get_temp_dir(), 'esia_sign_');

        file_put_contents($tmpData, $data);
        file_put_contents($tmpSign, $signature);

        $cmd = sprintf(
            '%s -verify -thumbprint "%s" "%s" "%s"',
            escapeshellcmd('/opt/cprocsp/bin/amd64/cryptcp'),
            escapeshellarg($thumbprint),
            escapeshellarg($tmpData),
            escapeshellarg($tmpSign)
        );

        exec($cmd . ' 2>&1', $output, $code);

        if ($code !== 0) {
            $errorMessage = implode("\n", $output);
            throw new \RuntimeException('CryptoPro verify failed: ' . $errorMessage);
        }

        return true;
    }
}
