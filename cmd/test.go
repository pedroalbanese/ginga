package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/bits"

	"github.com/pedroalbanese/whirlx"
)

// --- WhirlX Helper ---

func EncryptWhirlX(plain, key []byte) ([]byte, error) {
	if len(plain) != whirlx.BlockSize {
		return nil, fmt.Errorf("WhirlX: plaintext deve ter %d bytes", whirlx.BlockSize)
	}

	block, err := whirlx.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, whirlx.BlockSize)
	block.Encrypt(ciphertext, plain)

	return ciphertext, nil
}

func DecryptWhirlX(ciphertext, key []byte) ([]byte, error) {
	block, err := whirlx.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plain := make([]byte, whirlx.BlockSize)
	block.Decrypt(plain, ciphertext)

	return plain, nil
}

// --- Utils ---

func bitDiff(a, b []byte) int {
	diff := 0
	for i := range a {
		diff += bits.OnesCount8(a[i] ^ b[i])
	}
	return diff
}

// --- Testes ---

func testAvalancheKey(plain, key []byte) {
	fmt.Println("\n🌪 Avalanche na Chave (WhirlX):")
	original, _ := EncryptWhirlX(plain, key)

	for i := 0; i < len(key)*8; i++ {
		modKey := make([]byte, len(key))
		copy(modKey, key)
		modKey[i/8] ^= 1 << (i % 8)

		modCipher, _ := EncryptWhirlX(plain, modKey)
		diff := bitDiff(original, modCipher)
		fmt.Printf("Bit %3d modificado → Diferença: %3d bits (%.2f%%)\n", i, diff, 100*float64(diff)/128.0)
	}
}

func testAvalanchePlain(plain, key []byte) {
	fmt.Println("\n🌊 Avalanche no Plaintext (WhirlX):")
	original, _ := EncryptWhirlX(plain, key)

	for i := 0; i < len(plain)*8; i++ {
		modPlain := make([]byte, len(plain))
		copy(modPlain, plain)
		modPlain[i/8] ^= 1 << (i % 8)

		modCipher, _ := EncryptWhirlX(modPlain, key)
		diff := bitDiff(original, modCipher)
		fmt.Printf("Bit %3d modificado → Diferença: %3d bits (%.2f%%)\n", i, diff, 100*float64(diff)/128.0)
	}
}

func testGlobalAvalanchePlain(plain, key []byte) {
	original, _ := EncryptWhirlX(plain, key)
	fmt.Println("\n🌪 Teste Global de Avalanche no Plaintext (vários vetores):")

	const numTests = 1000
	const inputLen = whirlx.BlockSize
	const totalBits = inputLen * 8

	diffs := make([]int, 0, numTests*totalBits)

	for t := 0; t < numTests; t++ {
		plain := make([]byte, inputLen)
		rand.Read(plain)
		original, _ := EncryptWhirlX(plain, key)

		for i := 0; i < totalBits; i++ {
			modPlain := make([]byte, inputLen)
			copy(modPlain, plain)

			modPlain[i/8] ^= 1 << (i % 8)

			modCipher, _ := EncryptWhirlX(modPlain, key)
			diff := bitDiff(original, modCipher)
			diffs = append(diffs, diff)
		}
	}

	// Estatísticas
	sum := 0.0
	min := 999
	max := 0
	for _, d := range diffs {
		sum += float64(d)
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}
	mean := sum / float64(len(diffs))

	stddevSum := 0.0
	for _, d := range diffs {
		stddevSum += math.Pow(float64(d)-mean, 2)
	}
	stddev := math.Sqrt(stddevSum / float64(len(diffs)))

	fmt.Printf("Total de flips: %d\n", len(diffs))
	fmt.Printf("Média de bits alterados: %.2f / %d (%.2f%%)\n", mean, len(diffs)/numTests, 100*mean/float64(len(original)*8))
	fmt.Printf("Desvio padrão: %.2f bits\n", stddev)
	fmt.Printf("Mínimo: %d bits, Máximo: %d bits\n", min, max)
}

func testDifferentialResistance(plain, key []byte) {
	original, _ := whirlx.Encrypt(plain, key)
	mod := make([]byte, len(plain))
	copy(mod, plain)
	mod[len(mod)-1] ^= 0xFF

	altered, _ := whirlx.Encrypt(mod, key)
	diff := bitDiff(original, altered)

	fmt.Println("\n🔁 Teste de Resistência Diferencial (último byte flip):")
	fmt.Printf("Diferença entre ciphers: %d bits (%.2f%%)\n", diff, 100*float64(diff)/128.0)
}

func testInversibility(key []byte) {
	fmt.Println("\n♻️ Inversibilidade WhirlX:")
	for i := 0; i < 1000; i++ {
		plain := make([]byte, whirlx.BlockSize)
		rand.Read(plain)

		cipher, _ := EncryptWhirlX(plain, key)
		if len(cipher) != whirlx.BlockSize {
			fmt.Println("❌ Erro no tamanho do ciphertext!")
			return
		}
	}
	fmt.Println("✅ Todos os 1000 vetores testados com sucesso!")
}

func testByteUniformity(key []byte) {
	fmt.Println("\n📈 Uniformidade dos Bytes (WhirlX):")
	counts := make([]int, 256)
	samples := 10000

	for i := 0; i < samples; i++ {
		plain := make([]byte, whirlx.BlockSize)
		rand.Read(plain)
		c, _ := EncryptWhirlX(plain, key)

		for _, b := range c {
			counts[b]++
		}
	}

	entropia := 0.0
	total := float64(whirlx.BlockSize * samples)
	for _, v := range counts {
		p := float64(v) / total
		if p > 0 {
			entropia -= p * math.Log2(p)
		}
	}
	fmt.Printf("Entropia estimada: %.4f bits (máx. teórica: 8.0)\n", entropia)
}

func testDiffusion(key []byte) {
	fmt.Println("\n🌐 Teste de Difusão (WhirlX):")
	base := make([]byte, whirlx.BlockSize)
	rand.Read(base)
	original, _ := EncryptWhirlX(base, key)

	for i := 0; i < len(base); i++ {
		mod := make([]byte, len(base))
		copy(mod, base)
		mod[i] ^= 0xFF

		modCipher, _ := EncryptWhirlX(mod, key)
		byteDiff := 0
		for j := range modCipher {
			if modCipher[j] != original[j] {
				byteDiff++
			}
		}
		fmt.Printf("Byte %2d modificado → %2d/%2d bytes diferentes\n", i, byteDiff, len(modCipher))
	}
}

func testChiSquared(key []byte) {
	fmt.Println("\n📊 Teste de Chi-Squared para Avaliar Uniformidade (WhirlX):")
	const samples = 80000
	byteCounts := make([]int, 256)

	for i := 0; i < samples; i++ {
		plain := make([]byte, whirlx.BlockSize)
		rand.Read(plain)
		cipher, _ := EncryptWhirlX(plain, key)

		for _, b := range cipher {
			byteCounts[b]++
		}
	}

	expected := float64(whirlx.BlockSize*samples) / 256.0
	chiSquared := 0.0
	for _, observed := range byteCounts {
		diff := float64(observed) - expected
		chiSquared += (diff * diff) / expected
	}

	fmt.Printf("Valor do Teste Chi-Squared: %.2f\n", chiSquared)
}

// --- MAIN ---

func main() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210") // 16 bytes (WhirlX-128)
	plain := []byte("Shmon CipherTest")                            // 16 bytes (128 bits)

	fmt.Printf("🔐 Key:        %x\n", key)
	fmt.Printf("📥 Plaintext:  %s\n", plain)

	cipher, _ := EncryptWhirlX(plain, key)
	fmt.Printf("🔒 Ciphertext: %x\n", cipher)

	//	testAvalancheKey(plain, key)
	//	testAvalanchePlain(plain, key)
	testGlobalAvalanchePlain(plain, key)
	testChiSquared(key)
	testDifferentialResistance(plain, key)
	testInversibility(key)
	testByteUniformity(key)
	testDiffusion(key)
}
