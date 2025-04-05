package whirlx

import (
	"errors"
	"math/bits"
)

// Cifra ARX reversível de 16 bytes com chave de 16 ou 32 bytes
const BlockSize = 16
const Rounds = 10

func add(x, y byte) byte      { return x + y }
func sub(x, y byte) byte      { return x - y }
func rotl(x byte, n int) byte { return bits.RotateLeft8(x, n) }
func rotr(x byte, n int) byte { return bits.RotateLeft8(x, -n) }

func confuse(x byte) byte   { return rotl(x^0xA5, 3) }
func deconfuse(x byte) byte { return rotr(x, 3) ^ 0xA5 }

func mixState(state []byte) {
	for i := 0; i < len(state); i++ {
		state[i] = rotl(state[i]^state[(i+1)%len(state)], 3)
	}
}

func invMixState(state []byte) {
	for i := len(state) - 1; i >= 0; i-- {
		state[i] = rotr(state[i], 3) ^ state[(i+1)%len(state)]
	}
}

func round(x, k byte, r int) byte {
	x = add(x, k)
	x = confuse(x)
	x = rotl(x, (r+3)%8)
	x ^= k
	x = rotl(x, (r+5)%8)
	return x
}

func invRound(x, k byte, r int) byte {
	x = rotr(x, (r+5)%8)
	x ^= k
	x = rotr(x, (r+3)%8)
	x = deconfuse(x)
	x = sub(x, k)
	return x
}

func subKey(k []byte, round, i int) byte {
	base := k[(i+round)%len(k)]
	base = rotl(base^byte(i*73+round*91), (round+i)%8)
	return base
}

// Encrypt cifra um bloco de 16 bytes com uma chave de 16 ou 32 bytes
func Encrypt(plain, key []byte) ([]byte, error) {
	if len(plain) != BlockSize {
		return nil, errors.New("invalid plaintext size: must be 16 bytes")
	}
	if len(key) != 16 && len(key) != 32 {
		return nil, errors.New("invalid key size: must be 16 or 32 bytes")
	}

	c := make([]byte, BlockSize)
	copy(c, plain)

	for r := 0; r < Rounds; r++ {
		for i := range c {
			k := subKey(key, r, i)
			c[i] = round(c[i], k, r)
		}
		mixState(c)
	}
	return c, nil
}

// Decrypt reverte o bloco cifrado usando a chave
func Decrypt(cipher, key []byte) ([]byte, error) {
	if len(cipher) != BlockSize {
		return nil, errors.New("invalid cipher size: must be 16 bytes")
	}
	if len(key) != 16 && len(key) != 32 {
		return nil, errors.New("invalid key size: must be 16 or 32 bytes")
	}

	p := make([]byte, BlockSize)
	copy(p, cipher)

	for r := Rounds - 1; r >= 0; r-- {
		invMixState(p)
		for i := range p {
			k := subKey(key, r, i)
			p[i] = invRound(p[i], k, r)
		}
	}
	return p, nil
}
