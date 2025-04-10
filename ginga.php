<?php

define('BLOCK_SIZE', 16);
define('ROUNDS', 16);

// --- Funções auxiliares ARX ---

function rotl32($x, $n) {
    return (($x << $n) | ($x >> (32 - $n))) & 0xFFFFFFFF;
}

function rotr32($x, $n) {
    return (($x >> $n) | ($x << (32 - $n))) & 0xFFFFFFFF;
}

function confuse32($x) {
    $x ^= 0xA5A5A5A5;
    $x = ($x + 0x3C3C3C3C) & 0xFFFFFFFF;
    $x = rotl32($x, 7);
    return $x;
}

function deconfuse32($x) {
    $x = rotr32($x, 7);
    $x = ($x - 0x3C3C3C3C) & 0xFFFFFFFF;
    $x ^= 0xA5A5A5A5;
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

function invRound32($x, $k, $r) {
    $x = rotr32($x, ($r + 5) & 31);
    $x ^= $k;
    $x = rotr32($x, ($r + 3) & 31);
    $x = deconfuse32($x);
    $x = ($x - $k) & 0xFFFFFFFF;
    return $x;
}

function subKey32($k, $round, $i) {
    $base = $k[($i + $round) & 7];
    return rotl32($base ^ ($i * 73 + $round * 91), ($round + $i) & 31);
}

function mixState32(&$s) {
    $s[0] ^= rotl32($s[1], 5);
    $s[1] ^= rotl32($s[2], 11);
    $s[2] ^= rotl32($s[3], 17);
    $s[3] ^= rotl32($s[0], 23);
}

function invMixState32(&$s) {
    $s[3] ^= rotl32($s[0], 23);
    $s[2] ^= rotl32($s[3], 17);
    $s[1] ^= rotl32($s[2], 11);
    $s[0] ^= rotl32($s[1], 5);
}

function encryptBlock($plain, $key) {
    $c = array_values(unpack("V*", $plain));
    $k = array_values(unpack("V*", $key));

    for ($r = 0; $r < ROUNDS; $r++) {
        for ($i = 0; $i < 4; $i++) {
            $subk = subKey32($k, $r, $i);
            $c[$i] = round32($c[$i], $subk, $r);
        }
        mixState32($c);
    }
    return pack("V*", ...$c);
}

function decryptBlock($cipher, $key) {
    $p = array_values(unpack("V*", $cipher));
    $k = array_values(unpack("V*", $key));

    for ($r = ROUNDS - 1; $r >= 0; $r--) {
        invMixState32($p);
        for ($i = 0; $i < 4; $i++) {
            $subk = subKey32($k, $r, $i);
            $p[$i] = invRound32($p[$i], $subk, $r);
        }
    }
    return pack("V*", ...$p);
}

function ctrMode($data, $key, $nonce) {
    $output = '';
    $blockCount = ceil(strlen($data) / BLOCK_SIZE);

    for ($i = 0; $i < $blockCount; $i++) {
        $counter = substr_replace($nonce, pack("N", $i), 12, 4); // ← Corrigido aqui
        $keystream = encryptBlock($counter, $key);

        $block = substr($data, $i * BLOCK_SIZE, BLOCK_SIZE);
        $output .= $block ^ substr($keystream, 0, strlen($block));
    }

    return $output;
}

// --- Exemplo de uso ---

$key = str_repeat("\x00", 32);   // 256 bits = 32 bytes, todos 0x00
$nonce = str_repeat("\x00", 16); // 128 bits = 16 bytes, todos 0x00
$plaintext = "Mensagem confidencial com Ginga-CTR em PHP";


$ciphertext = ctrMode($plaintext, $key, $nonce);
$decrypted = ctrMode($ciphertext, $key, $nonce);

echo "Plaintext : " . trim($plaintext) . PHP_EOL;
echo "Ciphertext (hex): " . bin2hex($ciphertext) . PHP_EOL;
echo "Decrypted : " . trim($decrypted) . PHP_EOL;
