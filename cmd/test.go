package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/bits"

	"github.com/pedroalbanese/whirlx"
)

func bitDiff(a, b []byte) int {
	diff := 0
	for i := 0; i < len(a) && i < len(b); i++ {
		diff += bits.OnesCount8(a[i] ^ b[i])
	}
	return diff
}

func testAvalancheKey(plain, key []byte) {
	original, _ := whirlx.Encrypt(plain, key)
	fmt.Println("\n🌪 Teste de Avalanche na Chave:")
	for i := 0; i < len(key)*8; i++ {
		modKey := make([]byte, len(key))
		copy(modKey, key)
		byteIndex := i / 8
		bitIndex := i % 8
		modKey[byteIndex] ^= 1 << bitIndex

		modCipher, _ := whirlx.Encrypt(plain, modKey)
		diff := bitDiff(original, modCipher)
		fmt.Printf("Bit %3d modificado → Diferença: %3d bits (%.2f%%)\n", i, diff, 100*float64(diff)/float64(len(original)*8))
	}
}

func testAvalanchePlain(plain, key []byte) {
	original, _ := whirlx.Encrypt(plain, key)
	fmt.Println("\n🌊 Teste de Avalanche no Plaintext:")
	for i := 0; i < len(plain)*8; i++ {
		modPlain := make([]byte, len(plain))
		copy(modPlain, plain)
		byteIndex := i / 8
		bitIndex := i % 8
		modPlain[byteIndex] ^= 1 << bitIndex

		modCipher, _ := whirlx.Encrypt(modPlain, key)
		diff := bitDiff(original, modCipher)
		fmt.Printf("Bit %3d modificado → Diferença: %3d bits (%.2f%%)\n", i, diff, 100*float64(diff)/float64(len(original)*8))
	}
}

func testDifferentialResistance(plain, key []byte) {
	original, _ := whirlx.Encrypt(plain, key)
	mod := make([]byte, len(plain))
	copy(mod, plain)
	mod[len(mod)-1] ^= 0xFF

	altered, _ := whirlx.Encrypt(mod, key)
	diff := bitDiff(original, altered)

	fmt.Println("\n🔁 Teste de Resistência Diferencial (último byte flip):")
	fmt.Printf("Diferença entre ciphers: %d bits (%.2f%%)\n", diff, 100*float64(diff)/float64(len(original)*8))
}

func testBitDistribution(key []byte) {
	fmt.Println("\n📊 Teste de Distribuição de Bits na Saída:")
	totalBits := 0
	ones := 0

	for i := 0; i < 10000; i++ {
		plain := make([]byte, 16)
		_, _ = rand.Read(plain)

		c, _ := whirlx.Encrypt(plain, key)
		for _, b := range c {
			ones += bits.OnesCount8(b)
			totalBits += 8
		}
	}
	fmt.Printf("Bits '1' na saída: %d / %d (%.2f%%)\n", ones, totalBits, 100*float64(ones)/float64(totalBits))
}

func testInversibility(key []byte) {
	fmt.Println("\n🔁 Teste de Inversibilidade com vetores aleatórios:")
	for i := 0; i < 1000; i++ {
		plain := make([]byte, 16)
		_, _ = rand.Read(plain)

		cipher, _ := whirlx.Encrypt(plain, key)
		decrypted, _ := whirlx.Decrypt(cipher, key)

		if !bytes.Equal(plain, decrypted) {
			fmt.Printf("❌ Falha na inversão!\nOriginal: %x\nDecrypted: %x\n", plain, decrypted)
			return
		}
	}
	fmt.Println("✅ Todos os 1000 testes passaram com sucesso!")
}

func testByteUniformity(key []byte) {
	fmt.Println("\n📈 Teste de Uniformidade dos Bytes na Saída:")
	counts := make([]int, 256)
	samples := 10000

	for i := 0; i < samples; i++ {
		plain := make([]byte, 16)
		_, _ = rand.Read(plain)

		c, _ := whirlx.Encrypt(plain, key)
		for _, b := range c {
			counts[b]++
		}
	}

	entropia := 0.0
	total := float64(16 * samples)
	for _, v := range counts {
		p := float64(v) / total
		if p > 0 {
			entropia -= p * math.Log2(p)
		}
	}
	fmt.Printf("Entropia estimada: %.4f bits (máx. teórica: 8.0)\n", entropia)
}

func testDiffusion(key []byte) {
	fmt.Println("\n🌐 Teste de Difusão (alteração por byte):")
	base := make([]byte, 16)
	_, _ = rand.Read(base)

	original, _ := whirlx.Encrypt(base, key)

	for i := 0; i < len(base); i++ {
		mod := make([]byte, 16)
		copy(mod, base)
		mod[i] ^= 0xFF

		modCipher, _ := whirlx.Encrypt(mod, key)
		byteDiff := 0
		for j := 0; j < len(modCipher); j++ {
			if modCipher[j] != original[j] {
				byteDiff++
			}
		}
		fmt.Printf("Alteração no byte %2d → %2d/%2d bytes diferentes\n", i, byteDiff, len(modCipher))
	}
}

func main() {
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef")
	plain := []byte("Shmon CipherTest") // 16 bytes certinho

	cipher, _ := whirlx.Encrypt(plain, key)
	decrypted, _ := whirlx.Decrypt(cipher, key)

	fmt.Printf("🔐 Key:         %x\n", key)
	fmt.Printf("📥 Plaintext:   %s\n", plain)
	fmt.Printf("🔒 Ciphertext:  %x\n", cipher)
	fmt.Printf("🔓 Decrypted:   %s\n", decrypted)

	if !bytes.Equal(plain, decrypted) {
		fmt.Printf("❌ Decrypt FAIL: %x != %x\n", decrypted, plain)
	} else {
		fmt.Println("✅ Decrypt SUCCESS!")
	}

	testAvalancheKey(plain, key)
	testAvalanchePlain(plain, key)
	testDifferentialResistance(plain, key)
	testBitDistribution(key)
	testInversibility(key)
	testByteUniformity(key)
	testDiffusion(key)
}
