package ginga

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

const (
	BlockSize      = 32
	DigestSize     = 32
	internalRounds = 8
)

type gingaHash struct {
	state [16]uint32
	buf   []byte
	len   uint64
}

func New() hash.Hash {
	return &gingaHash{
		state: [16]uint32{
			0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
			0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
			0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
			0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
		},
		buf: make([]byte, 0, BlockSize),
		len: 0,
	}
}

func (h *gingaHash) Write(p []byte) (n int, err error) {
	h.buf = append(h.buf, p...)
	h.len += uint64(len(p))

	for len(h.buf) >= BlockSize {
		h.processBlock(h.buf[:BlockSize])
		h.buf = h.buf[BlockSize:]
	}
	return len(p), nil
}

/*
func (h *gingaHash) Sum(b []byte) []byte {
	tmp := make([]byte, len(h.buf))
	copy(tmp, h.buf)

	tmp = append(tmp, 0x80)
	for len(tmp)%BlockSize != 8 {
		tmp = append(tmp, 0x00)
	}

	lenBits := h.len * 8
	lenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBytes, lenBits)
	tmp = append(tmp, lenBytes...)

	for len(tmp) >= BlockSize {
		h.processBlock(tmp[:BlockSize])
		tmp = tmp[BlockSize:]
	}

	out := make([]byte, DigestSize)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(out[i*4:(i+1)*4], h.state[i])
	}
	return append(b, out...)
}
*/

func (h *gingaHash) Sum(b []byte) []byte {
	tmp := make([]byte, len(h.buf))
	copy(tmp, h.buf)

	tmp = append(tmp, 0x80)

	// Calcula o total de bytes finais: padding + 8 bytes do comprimento
	paddingSize := (BlockSize - (len(tmp)+8)%BlockSize) % BlockSize
	tmp = append(tmp, make([]byte, paddingSize)...)

	lenBits := h.len * 8
	lenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBytes, lenBits)
	tmp = append(tmp, lenBytes...)

	// Agora tmp tem tamanho múltiplo de BlockSize
	for len(tmp) >= BlockSize {
		h.processBlock(tmp[:BlockSize])
		tmp = tmp[BlockSize:]
	}

	out := make([]byte, DigestSize)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(out[i*4:(i+1)*4], h.state[i])
	}
	return append(b, out...)
}
	
func (h *gingaHash) Reset() {
	h.state = [16]uint32{
		0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
		0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
		0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
		0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
	}
	h.buf = h.buf[:0]
	h.len = 0
}

func (h *gingaHash) Size() int      { return DigestSize }
func (h *gingaHash) BlockSize() int { return BlockSize }

func (h *gingaHash) processBlock(block []byte) {
	var m [8]uint32 // bloco com 8 palavras de 32 bits
	for i := 0; i < 8; i++ {
		m[i] = binary.LittleEndian.Uint32(block[i*4 : (i+1)*4])
	}

	prev := h.state // salva o estado anterior

	// compressão com mais estado
	for r := 0; r < internalRounds; r++ {
		for i := 0; i < 16; i++ {
			k := subKey32(&m, r, i&7) // usa 8 palavras de mensagem
			h.state[i] = round32(h.state[i], k, r)
		}
		mixState512(&h.state)
	}

	// Miyaguchi-Preneel: H = f(H, M) ⊕ M ⊕ H_prev
	for i := 0; i < 16; i++ {
		h.state[i] ^= m[i&7] ^ prev[i]
	}
}

// ARX primitives

func rotl32(x uint32, n int) uint32 {
	return bits.RotateLeft32(x, n)
}

func confuse32(x uint32) uint32 {
	x ^= 0xA5A5A5A5
	x += 0x3C3C3C3C
	x = rotl32(x, 7)
	return x
}

func round32(x, k uint32, r int) uint32 {
	x += k
	x = confuse32(x)
	x = rotl32(x, (r+3)&31)
	x ^= k
	x = rotl32(x, (r+5)&31)
	return x
}

func subKey32(k *[8]uint32, round, i int) uint32 {
	base := k[(i+round)&7]
	return rotl32(base^uint32(i*73+round*91), (round+i)&31)
}

func mixState512(state *[16]uint32) {
	for i := 0; i < 16; i++ {
		state[i] ^= rotl32(state[(i+3)&15], (7*i+13)&31)
	}
}
