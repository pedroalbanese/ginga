package whirlx

import (
	"crypto/cipher"
	"errors"
	"math/bits"
)

// Constantes principais da cifra
const BlockSize = 16
const Rounds = 16

// --- Funções auxiliares ARX ---

func add(x, y byte) byte      { return x + y }
func sub(x, y byte) byte      { return x - y }
func rotl(x byte, n int) byte { return bits.RotateLeft8(x, n) }
func rotr(x byte, n int) byte { return bits.RotateLeft8(x, -n) }

// func confuse(x byte) byte   { return rotl(x^0xA5, 3) }
// func deconfuse(x byte) byte { return rotr(x, 3) ^ 0xA5 }

func confuse(x byte) byte {
	x ^= 0xA5        // 1. XOR
	x = add(x, 0x3C) // 2. ADD
	x = rotl(x, 3)   // 3. ROTATE LEFT
	return x
}

func deconfuse(x byte) byte {
	x = rotr(x, 3)   // 1. ROTATE RIGHT (inverse of rotl)
	x = sub(x, 0x3C) // 2. SUB (inverse of add)
	x ^= 0xA5        // 3. XOR (same as XOR inverse)
	return x
}

func confuseN(x byte, n int) byte {
	for i := 0; i < n; i++ {
		x = confuse(x)
	}
	return x
}

func deconfuseN(x byte, n int) byte {
	for i := 0; i < n; i++ {
		x = deconfuse(x)
	}
	return x
}

/*
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
*/

func mixState(state *[16]byte) {
	for i := 0; i < 16; i++ {
		state[i] = rotl(state[i]^state[(i+1)&15], 3)
	}
}

func invMixState(state *[16]byte) {
	for i := 15; i >= 0; i-- {
		state[i] = rotr(state[i], 3) ^ state[(i+1)&15]
	}
}

func round(x, k byte, r int) byte {
	x = add(x, k)
	x = confuseN(x, 4) // mais confusão!
//	x = rotl(x, (r+3)%8)
	x = rotl(x, (r+3)&7)
	x ^= k
//	x = rotl(x, (r+5)%8)
	x = rotl(x, (r+5)&7)
	return x
}

func invRound(x, k byte, r int) byte {
//	x = rotr(x, (r+5)%8)
	x = rotr(x, (r+5)&7)
	x ^= k
//	x = rotr(x, (r+3)%8)
	x = rotr(x, (r+3)&7)
	x = deconfuseN(x, 4)
	x = sub(x, k)
	return x
}

/*
func subKey(k []byte, round, i int) byte {
//	base := k[(i+round)%len(k)]
	base := k[(i+round)&15] // se len(k) == 16
	base = rotl(base^byte(i*73+round*91), (round+i)%8)
	return base
}
*/

func subKey(k []byte, round, i int) byte {
	var mask int
	switch len(k) {
	case 16:
		mask = 15 // 0b00001111
	case 32:
		mask = 31 // 0b00011111
	default:
		panic("subKey: chave inválida")
	}
	idx := (i + round) & mask // substitui % por &
	base := k[idx]
//	base = rotl(base^byte(i*73+round*91), (round+i)%8)
	base = rotl(base^byte(i*73+round*91), (round+i)&7)
	return base
}

// --- Funções principais de cifra ---

// Encrypt cifra um bloco de 16 bytes com uma chave de 16 ou 32 bytes
func Encrypt(plain, key []byte) ([]byte, error) {
	if len(plain) != BlockSize {
		return nil, errors.New("whirlx: invalid plaintext size (must be 16 bytes)")
	}
	if len(key) != 16 && len(key) != 32 {
		return nil, errors.New("whirlx: invalid key size (must be 16 or 32 bytes)")
	}

//	c := make([]byte, BlockSize)
//	copy(c, plain)

	var c [16]byte
	copy(c[:], plain)
	
	for r := 0; r < Rounds; r++ {
		for i := range c {
			k := subKey(key, r, i)
			c[i] = round(c[i], k, r)
		}
//		mixState(c)
		mixState(c[:])
	}
//	return c, nil
	return c[:], nil
}

// Decrypt reverte o bloco cifrado usando a chave
func Decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) != BlockSize {
		return nil, errors.New("whirlx: invalid cipher size (must be 16 bytes)")
	}
	if len(key) != 16 && len(key) != 32 {
		return nil, errors.New("whirlx: invalid key size (must be 16 or 32 bytes)")
	}

//	p := make([]byte, BlockSize)
//	copy(p, ciphertext)

	var p [16]byte
	copy(p[:], ciphertext)
	
	for r := Rounds - 1; r >= 0; r-- {
		invMixState(p)
		for i := range p {
			k := subKey(key, r, i)
			p[i] = invRound(p[i], k, r)
		}
	}
//	return p, nil
	return p[:], nil
}

// --- Integração com cipher.Block (NewCipher) ---

type whirlxCipher struct {
	key []byte
}

// NewCipher cria um objeto cipher.Block compatível com modos de operação
func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, errors.New("whirlx: invalid key size (must be 16 or 32 bytes)")
	}
	return &whirlxCipher{key: append([]byte(nil), key...)}, nil
}

// BlockSize retorna o tamanho do bloco da cifra (16 bytes)
func (c *whirlxCipher) BlockSize() int {
	return BlockSize
}

// Encrypt cifra exatamente um bloco de 16 bytes
func (c *whirlxCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize || len(dst) < BlockSize {
		panic("whirlx: input not full block")
	}
	out, err := Encrypt(src[:BlockSize], c.key)
	if err != nil {
		panic("whirlx: encryption failed: " + err.Error())
	}
	copy(dst, out)
}

// Decrypt decifra exatamente um bloco de 16 bytes
func (c *whirlxCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize || len(dst) < BlockSize {
		panic("whirlx: input not full block")
	}
	out, err := Decrypt(src[:BlockSize], c.key)
	if err != nil {
		panic("whirlx: decryption failed: " + err.Error())
	}
	copy(dst, out)
}
