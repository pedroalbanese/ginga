<?php

define('GINGA_BLOCK_SIZE', 32);
define('GINGA_DIGEST_SIZE', 32);
define('GINGA_ROUNDS', 8);

// --- Funções auxiliares ARX ---
function rotl32($x, $n) {
    return (($x << $n) | ($x >> (32 - $n))) & 0xFFFFFFFF;
}

function confuse32($x) {
    $x ^= 0xA5A5A5A5;
    $x = ($x + 0x3C3C3C3C) & 0xFFFFFFFF;
    $x = rotl32($x, 7);
    return $x;
}

function round32($x, $k, $r) {
    $x = ($x + $k) & 0xFFFFFFFF;
    $x = confuse32($x);
    $x = rotl32($x, ($r + 3) & 31);
    $x ^= $k;
    $x = rotl32($x, ($r + 5) & 31);
    return $x;
}

function subKey32($k, $round, $i) {
    $base = $k[($i + $round) & 7];
    return rotl32($base ^ ($i * 73 + $round * 91), ($round + $i) & 31);
}

function mixState512(&$state) {
    for ($i = 0; $i < 16; $i++) {
        $state[$i] ^= rotl32($state[($i + 3) & 15], (7 * $i + 13) & 31);
    }
}

// --- Hash Ginga ---
function gingaHash($msg) {
    $state = [
        0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
        0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
        0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
        0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    ];

    $len = strlen($msg);
    $msg .= chr(0x80);

    $padLen = (GINGA_BLOCK_SIZE - (strlen($msg) + 8) % GINGA_BLOCK_SIZE) % GINGA_BLOCK_SIZE;
    $msg .= str_repeat("\x00", $padLen);
    $msg .= pack("P", $len * 8); // little-endian 64-bit length

    for ($i = 0; $i < strlen($msg); $i += GINGA_BLOCK_SIZE) {
        $block = substr($msg, $i, GINGA_BLOCK_SIZE);
        $m = array_values(unpack("V*", $block));
        $prev = $state;

        for ($r = 0; $r < GINGA_ROUNDS; $r++) {
            for ($j = 0; $j < 16; $j++) {
                $k = subKey32($m, $r, $j & 7);
                $state[$j] = round32($state[$j], $k, $r);
            }
            mixState512($state);
        }

        for ($j = 0; $j < 16; $j++) {
            $state[$j] ^= $m[$j & 7] ^ $prev[$j];
        }
    }

    $digest = '';
    for ($i = 0; $i < 8; $i++) {
        $digest .= pack("V", $state[$i]);
    }
    return $digest;
}

function hmacGinga($key, $message) {
    $blockSize = GINGA_BLOCK_SIZE;

    // Passo 1: Ajustar tamanho da chave
    if (strlen($key) > $blockSize) {
        $key = gingaHash($key); // Reduz com hash
    }
    if (strlen($key) < $blockSize) {
        $key = str_pad($key, $blockSize, "\0"); // Preenche com zeros
    }

    // Passo 2: Criar o padding interno e externo
    $o_key_pad = $i_key_pad = '';
    for ($i = 0; $i < $blockSize; $i++) {
        $k = ord($key[$i]);
        $o_key_pad .= chr($k ^ 0x5c);
        $i_key_pad .= chr($k ^ 0x36);
    }

    // Passo 3: Aplicar HMAC
    $innerHash = gingaHash($i_key_pad . $message);
    return gingaHash($o_key_pad . $innerHash);
}

// --- Exemplo de uso ---
$key = "chave-secreta";
$mensagem = "Exemplo da função hash Ginga em PHP.";
$hash = gingaHash($mensagem);

$hmac = hmacGinga($key, $mensagem);

echo "Mensagem: " . $mensagem . PHP_EOL;
echo "Hash (hex): " . bin2hex($hash) . PHP_EOL;
echo "HMAC-Ginga (hex): " . bin2hex($hmac) . PHP_EOL;
