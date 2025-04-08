package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/bits"
	"time"
	"sort"

	"github.com/pedroalbanese/ginga"
)

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
	fmt.Println("\n🌪 Avalanche na Chave (Ginga):")
	original, _ := ginga.Encrypt(plain, key)

	for i := 0; i < len(key)*8; i++ {
		modKey := make([]byte, len(key))
		copy(modKey, key)
		modKey[i/8] ^= 1 << (i % 8)

		modCipher, _ := ginga.Encrypt(plain, modKey)
		diff := bitDiff(original, modCipher)
		fmt.Printf("Bit %3d modificado → Diferença: %3d bits (%.2f%%)\n", i, diff, 100*float64(diff)/128.0)
	}
}

func testAvalanchePlain(plain, key []byte) {
	fmt.Println("\n🌊 Avalanche no Plaintext (Ginga):")
	original, _ := ginga.Encrypt(plain, key)

	for i := 0; i < len(plain)*8; i++ {
		modPlain := make([]byte, len(plain))
		copy(modPlain, plain)
		modPlain[i/8] ^= 1 << (i % 8)

		modCipher, _ := ginga.Encrypt(modPlain, key)
		diff := bitDiff(original, modCipher)
		fmt.Printf("Bit %3d modificado → Diferença: %3d bits (%.2f%%)\n", i, diff, 100*float64(diff)/128.0)
	}
}

func testGlobalAvalanchePlain(plain, key []byte) {
	original, _ := ginga.Encrypt(plain, key)
	fmt.Println("\n🌪 Teste Global de Avalanche no Plaintext (vários vetores):")

	const numTests = 1000
	const inputLen = ginga.BlockSize
	const totalBits = inputLen * 8

	diffs := make([]int, 0, numTests*totalBits)

	for t := 0; t < numTests; t++ {
		plain := make([]byte, inputLen)
		rand.Read(plain)
		original, _ := ginga.Encrypt(plain, key)

		for i := 0; i < totalBits; i++ {
			modPlain := make([]byte, inputLen)
			copy(modPlain, plain)

			modPlain[i/8] ^= 1 << (i % 8)

			modCipher, _ := ginga.Encrypt(modPlain, key)
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
	fmt.Println("\n🔁 Resistência Diferencial (Ginga):")
	original, _ := ginga.Encrypt(plain, key)
	mod := make([]byte, len(plain))
	copy(mod, plain)
	mod[len(mod)-1] ^= 0xFF

	altered, _ := ginga.Encrypt(mod, key)
	diff := bitDiff(original, altered)
	fmt.Printf("Alterando último byte → Diferença: %d bits (%.2f%%)\n", diff, 100*float64(diff)/128.0)
}

func testBitDistribution(key []byte) {
	fmt.Println("\n📊 Teste de Distribuição de Bits na Saída:")
	totalBits, ones := 0, 0

	for i := 0; i < 10000; i++ {
		plain := make([]byte, 16)
		rand.Read(plain)

		c, _ := ginga.Encrypt(plain, key)
		for _, b := range c {
			ones += bits.OnesCount8(b)
			totalBits += 8
		}
	}
	fmt.Printf("Bits '1' na saída: %d / %d (%.2f%%)\n", ones, totalBits, 100*float64(ones)/float64(totalBits))
}

func testInversibility(key []byte) {
	fmt.Println("\n♻️ Inversibilidade Ginga:")
	for i := 0; i < 1000; i++ {
		plain := make([]byte, ginga.BlockSize)
		rand.Read(plain)

		cipher, _ := ginga.Encrypt(plain, key)
		if len(cipher) != ginga.BlockSize {
			fmt.Println("❌ Erro no tamanho do ciphertext!")
			return
		}
	}
	fmt.Println("✅ Todos os 1000 vetores testados com sucesso!")
}

func testByteUniformity(key []byte) {
	fmt.Println("\n📈 Uniformidade dos Bytes (Ginga):")
	counts := make([]int, 256)
	samples := 10000

	for i := 0; i < samples; i++ {
		plain := make([]byte, ginga.BlockSize)
		rand.Read(plain)
		c, _ := ginga.Encrypt(plain, key)

		for _, b := range c {
			counts[b]++
		}
	}

	entropia := 0.0
	total := float64(ginga.BlockSize * samples)
	for _, v := range counts {
		p := float64(v) / total
		if p > 0 {
			entropia -= p * math.Log2(p)
		}
	}
	fmt.Printf("Entropia estimada: %.4f bits (máx. teórica: 8.0)\n", entropia)
}

func testDiffusion(key []byte) {
	fmt.Println("\n🌐 Teste de Difusão (Ginga):")
	base := make([]byte, ginga.BlockSize)
	rand.Read(base)
	original, _ := ginga.Encrypt(base, key)

	for i := 0; i < len(base); i++ {
		mod := make([]byte, len(base))
		copy(mod, base)
		mod[i] ^= 0xFF

		modCipher, _ := ginga.Encrypt(mod, key)
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
	fmt.Println("\n📊 Teste de Chi-Squared para Avaliar Uniformidade (Ginga):")
	const samples = 80000
	byteCounts := make([]int, 256)

	for i := 0; i < samples; i++ {
		plain := make([]byte, ginga.BlockSize)
		rand.Read(plain)
		cipher, _ := ginga.Encrypt(plain, key)

		for _, b := range cipher {
			byteCounts[b]++
		}
	}

	expected := float64(ginga.BlockSize*samples) / 256.0
	chiSquared := 0.0
	for _, observed := range byteCounts {
		diff := float64(observed) - expected
		chiSquared += (diff * diff) / expected
	}

	fmt.Printf("Valor do Teste Chi-Squared: %.2f\n", chiSquared)
}

// Teste de Criptoanálise Linear
func testLinearCryptanalysis(key []byte) {
	// Usando máscaras comuns: 0x55 (01010101) para o plaintext e 0xAA (10101010) para o ciphertext.
	const numTests = 5000
	maskPlain := byte(0x55)
	maskCipher := byte(0xAA)
	matches := 0

	for i := 0; i < numTests; i++ {
		p := make([]byte, ginga.BlockSize)
		rand.Read(p)
		c, err := ginga.Encrypt(p, key)
		if err != nil {
			continue
		}

		// Calcula a paridade dos bits selecionados pelas máscaras
		pParity := 0
		cParity := 0
		for j := 0; j < ginga.BlockSize; j++ {
			pParity ^= bits.OnesCount8(p[j]&maskPlain) & 1
			cParity ^= bits.OnesCount8(c[j]&maskCipher) & 1
		}

		if pParity == cParity {
			matches++
		}
	}

	ratio := float64(matches) / float64(numTests)
	fmt.Println("\n📉 Teste de Criptoanálise Linear:")
	fmt.Printf("Correlação observada: %.4f (ideal: 0.5)\n", ratio)
}

func testBoomerang(key []byte) {
	fmt.Println("\n🪃 Teste Boomerang (melhorado):")
	samples := 1000

	//	deltas := []byte{0x01, 0x0F, 0x3C, 0xA5, 0xFF}
	deltas := []byte{
		0x01, // bit menos significativo
		0x02, // bit próximo
		0x08, // bit médio
		0x10, // mudança de nibble
		0x80, // bit mais significativo
		0xC0, // bits altos
		0xF0, // nibble alto
		0x3C, // padrão alternado
		0xA5, // padrão alternado invertido
		0xFF, // todos os bits
	}

	bestCorr := 0.0
	var bestDeltaP, bestDeltaC byte

	for _, deltaP := range deltas {
		for _, deltaC := range deltas {
			matches := 0

			for i := 0; i < samples; i++ {
				P1 := make([]byte, 16)
				rand.Read(P1)

				P2 := make([]byte, 16)
				copy(P2, P1)
				P2[0] ^= deltaP // ΔP numa posição

				C1, _ := ginga.Encrypt(P1, key)
				C2, _ := ginga.Encrypt(P2, key)

				C1p := make([]byte, 16)
				C2p := make([]byte, 16)
				copy(C1p, C1)
				copy(C2p, C2)
				C1p[0] ^= deltaC // ΔC aplicada
				C2p[0] ^= deltaC

				D1, _ := ginga.Decrypt(C1p, key)
				D2, _ := ginga.Decrypt(C2p, key)

				// Checar se a diferença no output bate com deltaP
				if D1[0]^D2[0] == deltaP {
					matches++
				}
			}

			corr := float64(matches) / float64(samples)
			if corr > bestCorr {
				bestCorr = corr
				bestDeltaP = deltaP
				bestDeltaC = deltaC
			}
		}
	}

	fmt.Printf("🌟 Melhor ΔP: 0x%02X | ΔC: 0x%02X → Correlação: %.5f\n", bestDeltaP, bestDeltaC, bestCorr)
}

func testKeySaturation() {
	fmt.Println("\n🧊 Teste de Saturação da Chave:")
	patterns := [][]byte{
		bytes.Repeat([]byte{0x00}, 32),
		bytes.Repeat([]byte{0xFF}, 32),
		bytes.Repeat([]byte{0xAA}, 32),
		bytes.Repeat([]byte{0x55}, 32),
	}

	plain := make([]byte, 16)
	rand.Read(plain)

	for _, key := range patterns {
		cipher, _ := ginga.Encrypt(plain, key)
		fmt.Printf("Key: %x → Cipher: %x\n", key, cipher)
	}
}

func testRepetitivePlaintext(key []byte) {
	fmt.Println("\n🔁 Teste com Plaintext Repetitivo:")
	plain := bytes.Repeat([]byte{0x41}, 16) // "AAAAAAAAAAAAAAAA"
	cipher, _ := ginga.Encrypt(plain, key)
	fmt.Printf("Plain: %x → Cipher: %x\n", plain, cipher)
}

func testTripleByteDifference(key []byte) {
	fmt.Println("\n⚠️ Teste com 3 Bytes Diferentes:")
	plain := make([]byte, 16)
	rand.Read(plain)
	original, _ := ginga.Encrypt(plain, key)

	mod := make([]byte, 16)
	copy(mod, plain)
	mod[0] ^= 0xFF
	mod[5] ^= 0xFF
	mod[10] ^= 0xFF

	modCipher, _ := ginga.Encrypt(mod, key)
	diff := bitDiff(original, modCipher)
	fmt.Printf("Alterando 3 bytes → Diferença: %d bits (%.2f%%)\n", diff, 100*float64(diff)/128.0)
}

func testTimingVariance(key []byte) {
	fmt.Println("\n⏱ Teste de Variação de Tempo:")
	times := []time.Duration{}

	for i := 0; i < 1000; i++ {
		plain := make([]byte, 16)
		rand.Read(plain)
		start := time.Now()
		ginga.Encrypt(plain, key)
		times = append(times, time.Since(start))
	}

	// Ordena os tempos pra cortar o top 1%
	sort.Slice(times, func(i, j int) bool {
		return times[i] < times[j]
	})
	cutoff := int(float64(len(times)) * 0.99) // 99% dos tempos
	filtered := times[:cutoff]

	var total time.Duration
	min, max := filtered[0], filtered[0]
	for _, t := range filtered {
		total += t
		if t < min {
			min = t
		}
		if t > max {
			max = t
		}
	}
	avg := total / time.Duration(len(filtered))

	// Cálculo do desvio padrão
	var sumSquares float64
	for _, t := range filtered {
		diff := float64(t - avg)
		sumSquares += diff * diff
	}
	stdDev := time.Duration(math.Sqrt(sumSquares / float64(len(filtered))))

	fmt.Printf("Tempo médio: %v | Min: %v | Max (sem outliers): %v | Desvio padrão: ±%v\n", avg, min, max, stdDev)

	// Exibe os outliers
	for i := cutoff; i < len(times); i++ {
		fmt.Printf("⚠️  Outlier detectado: %v\n", times[i])
	}
}

// --- MAIN ---

func main() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210") // 32 bytes (Ginga-256)
	plain := []byte("Ginga CipherTest")                            // 16 bytes (128 bits)

	fmt.Printf("🔐 Key:        %x\n", key)
	fmt.Printf("📥 Plaintext:  %s\n", plain)

	cipher, _ := ginga.Encrypt(plain, key)
	fmt.Printf("🔒 Ciphertext: %x\n", cipher)

	decrypted, _ := ginga.Decrypt(cipher, key)
	fmt.Printf("🔓 Decrypted:  %s\n", decrypted)

	//	testAvalancheKey(plain, key)
	//	testAvalanchePlain(plain, key)
	testGlobalAvalanchePlain(plain, key)
	testChiSquared(key)
	testBitDistribution(key)
	testDifferentialResistance(plain, key)
	testInversibility(key)
	testByteUniformity(key)
	testDiffusion(key)
	testLinearCryptanalysis(key)
	testBoomerang(key)
	testKeySaturation()
	testRepetitivePlaintext(key)
	testTimingVariance(key)
}
