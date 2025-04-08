package ginga

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

const (
	BlockSize      = 16
	DigestSize     = 32
	internalRounds = 8
)

type gingaHash struct {
	state [8]uint32
	buf   []byte
	len   uint64
}

func New() hash.Hash {
	return &gingaHash{
		state: [8]uint32{
			0xDEADBEEF, 0xCAFEBABE, 0xFEEDFACE, 0xBAADF00D,
			0x8BADF00D, 0x1337C0DE, 0x0BADC0DE, 0xFACEB00C,
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

func (h *gingaHash) Reset() {
	h.state = [8]uint32{
		0xDEADBEEF, 0xCAFEBABE, 0xFEEDFACE, 0xBAADF00D,
		0x8BADF00D, 0x1337C0DE, 0x0BADC0DE, 0xFACEB00C,
	}
	h.buf = h.buf[:0]
	h.len = 0
}

func (h *gingaHash) Size() int      { return DigestSize }
func (h *gingaHash) BlockSize() int { return BlockSize }

func (h *gingaHash) processBlock(block []byte) {
	var m [4]uint32
	for i := 0; i < 4; i++ {
		m[i] = binary.LittleEndian.Uint32(block[i*4 : (i+1)*4])
	}

	prev := h.state // salva estado anterior

	// faz a compressão com os rounds
	for r := 0; r < internalRounds; r++ {
		for i := 0; i < 8; i++ {
			k := subKey32(&m, r, i&3)
			h.state[i] = round32(h.state[i], k, r)
		}
		mixState256(&h.state)
	}

	// aplica Miyaguchi-Preneel: H = f(H, M) ⊕ M ⊕ H
	for i := 0; i < 8; i++ {
		h.state[i] ^= m[i&3] ^ prev[i]
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

func subKey32(k *[4]uint32, round, i int) uint32 {
	base := k[(i+round)&3]
	return rotl32(base^uint32(i*73+round*91), (round+i)&31)
}

func mixState256(state *[8]uint32) {
	for i := 0; i < 8; i++ {
		state[i] ^= rotl32(state[(i+1)&7], (5*i+11)&31)
	}
}
