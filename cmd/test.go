package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/bits"

	"github.com/pedroalbanese/ginga"
	"github.com/RyuaNerin/go-krypto/lea"
	"github.com/deatil/go-cryptobin/cipher/speck"
)

// ================= UTILS =================

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func xorBytes(a, b []byte) []byte {
	r := make([]byte, len(a))
	for i := range a {
		r[i] = a[i] ^ b[i]
	}
	return r
}

func padPKCS7(b []byte, blockSize int) []byte {
	padLen := blockSize - (len(b) % blockSize)
	for i := 0; i < padLen; i++ {
		b = append(b, byte(padLen))
	}
	return b
}

func bitDiff(a, b []byte) int {
	diff := 0
	for i := 0; i < len(a); i++ {
		diff += bits.OnesCount8(a[i] ^ b[i])
	}
	return diff
}

// ================= AES =================

var aesKey = make([]byte, 16) // chave fixa para análise

func AESFunc(pt []byte) []byte {
	block, _ := aes.NewCipher(aesKey)
	ct := make([]byte, len(pt))
	block.Encrypt(ct, pt)
	return ct
}

// ================= GINGA =================

func GingaFunc(pt []byte) []byte {
	key := []byte("0123456789abcdef0123456789abcdef") // Chave de 256 bits
	block, err := ginga.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, len(pt))
	iv := make([]byte, ginga.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		panic(err)
	}
	block.Encrypt(ciphertext, pt)
	return ciphertext
}

// ================= LEA =================

var leaKey = []byte("0123456789abcdef0123456789abcdef") // Chave de 128 bits

func LEAFunc(pt []byte) []byte {
	block, _ := lea.NewCipher(leaKey)
	ct := make([]byte, len(pt))
	block.Encrypt(ct, pt)
	return ct
}

// ================= SPECK =================

var speckKey = []byte("0123456789abcdef0123456789abcdef") // Chave de 128 bits

func SpeckFunc(pt []byte) []byte {
	block, _ := speck.NewCipher(speckKey)
	ct := make([]byte, len(pt))
	block.Encrypt(ct, pt)
	return ct
}

// AES
func AESEncrypt(pt []byte, key []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	ct := make([]byte, len(pt))
	block.Encrypt(ct, pt)
	return ct, nil
}

func AESDecrypt(ct []byte, key []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	pt := make([]byte, len(ct))
	block.Decrypt(pt, ct)
	return pt, nil
}

// Ginga
func GingaEncrypt(pt []byte, key []byte) ([]byte, error) {
	block, err := ginga.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ct := make([]byte, len(pt))
	block.Encrypt(ct, pt)
	return ct, nil
}

func GingaDecrypt(ct []byte, key []byte) ([]byte, error) {
	block, err := ginga.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	block.Decrypt(pt, ct)
	return pt, nil
}

// LEA
func LEAEncrypt(pt []byte, key []byte) ([]byte, error) {
	block, _ := lea.NewCipher(key)
	ct := make([]byte, len(pt))
	block.Encrypt(ct, pt)
	return ct, nil
}

func LEADecrypt(ct []byte, key []byte) ([]byte, error) {
	block, _ := lea.NewCipher(key)
	pt := make([]byte, len(ct))
	block.Decrypt(pt, ct)
	return pt, nil
}

// Speck
func SpeckEncrypt(pt []byte, key []byte) ([]byte, error) {
	block, _ := speck.NewCipher(key)
	ct := make([]byte, len(pt))
	block.Encrypt(ct, pt)
	return ct, nil
}

func SpeckDecrypt(ct []byte, key []byte) ([]byte, error) {
	block, _ := speck.NewCipher(key)
	pt := make([]byte, len(ct))
	block.Decrypt(pt, ct)
	return pt, nil
}

// ================ Boomerang ================

func testBoomerang(name string, encryptFunc func([]byte, []byte) ([]byte, error), decryptFunc func([]byte, []byte) ([]byte, error), key []byte) {
	fmt.Printf("\n🪃 Teste Boomerang (%s):\n", name)
	samples := 1000

	deltas := []byte{
		0x01, 0x02, 0x08, 0x10, 0x80, 0xC0, 0xF0, 0x3C, 0xA5, 0xFF,
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
				P2[0] ^= deltaP

				C1, _ := encryptFunc(P1, key)
				C2, _ := encryptFunc(P2, key)

				C1p := make([]byte, 16)
				C2p := make([]byte, 16)
				copy(C1p, C1)
				copy(C2p, C2)
				C1p[0] ^= deltaC
				C2p[0] ^= deltaC

				D1, _ := decryptFunc(C1p, key)
				D2, _ := decryptFunc(C2p, key)

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

// ================ Chi² ================

func testChiSquared(name string, encryptFunc func([]byte) []byte, blockSize int) {
	fmt.Printf("\n📊 Teste de Chi-Squared para Uniformidade (%s):\n", name)

	const samples = 80000
	byteCounts := make([]int, 256)

	for i := 0; i < samples; i++ {
		plain := make([]byte, blockSize)
		rand.Read(plain)
		cipher := encryptFunc(plain)

		for _, b := range cipher {
			byteCounts[b]++
		}
	}

	expected := float64(blockSize*samples) / 256.0
	chiSquared := 0.0
	for _, observed := range byteCounts {
		diff := float64(observed) - expected
		chiSquared += (diff * diff) / expected
	}

	fmt.Printf("🔍 Valor Chi-Squared: %.2f\n", chiSquared)
}

// ================ DIFFUSION ================

func testDiffusion(name string, encryptFunc func([]byte) []byte, blockSize int) {
	fmt.Printf("\n🌐 Teste de Difusão (%s):\n", name)

	base := make([]byte, blockSize)
	rand.Read(base)
	original := encryptFunc(base)

	for i := 0; i < blockSize; i++ {
		mod := make([]byte, blockSize)
		copy(mod, base)
		mod[i] ^= 0xFF

		modCipher := encryptFunc(mod)
		byteDiff := 0
		for j := 0; j < len(modCipher); j++ {
			if modCipher[j] != original[j] {
				byteDiff++
			}
		}
		fmt.Printf("Byte %2d modificado → %2d/%2d bytes diferentes\n", i, byteDiff, blockSize)
	}
}

// ================ ByteUniformity ================

func testByteUniformity(name string, encryptFunc func([]byte) []byte, blockSize int) {
	fmt.Printf("\n📈 Uniformidade dos Bytes (%s):\n", name)

	counts := make([]int, 256)
	samples := 10000

	for i := 0; i < samples; i++ {
		plain := make([]byte, blockSize)
		rand.Read(plain)
		c := encryptFunc(plain)

		for _, b := range c {
			counts[b]++
		}
	}

	entropia := 0.0
	total := float64(blockSize * samples)
	for _, v := range counts {
		p := float64(v) / total
		if p > 0 {
			entropia -= p * math.Log2(p)
		}
	}
	fmt.Printf("Entropia estimada: %.4f bits (máx. teórica: 8.0)\n", entropia)
}

// ============ Bit Distribution ============

func testBitDistribution(name string, encryptFunc func([]byte) []byte, blockSize int) {
	fmt.Printf("\n📊 Teste de Distribuição de Bits na Saída (%s):\n", name)
	totalBits, ones := 0, 0

	for i := 0; i < 1000000; i++ {
		plain := make([]byte, blockSize)
		rand.Read(plain)

		c := encryptFunc(plain)
		for _, b := range c {
			ones += bits.OnesCount8(b)
			totalBits += 8
		}
	}
	fmt.Printf("Bits '1' na saída: %d / %d (%.2f%%)\n", ones, totalBits, 100*float64(ones)/float64(totalBits))
}

// ============ GlobalAvalanchePlain ============

func testGlobalAvalanchePlain(name string, encryptFunc func([]byte, []byte) ([]byte, error), key []byte, blockSize int) {
	fmt.Printf("\n🌪 Teste Global de Avalanche no Plaintext (%s):\n", name)

	const numTests = 10000
	const totalBits = 8 * 16 // assumindo blocos de 16 bytes

	diffs := make([]int, 0, numTests*totalBits)

	for t := 0; t < numTests; t++ {
		plain := make([]byte, blockSize)
		rand.Read(plain)

		original, err := encryptFunc(plain, key)
		if err != nil {
			panic(err)
		}

		for i := 0; i < totalBits; i++ {
			modPlain := make([]byte, blockSize)
			copy(modPlain, plain)

			modPlain[i/8] ^= 1 << (i % 8)

			modCipher, err := encryptFunc(modPlain, key)
			if err != nil {
				panic(err)
			}

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
	fmt.Printf("Média de bits alterados: %.2f / %d (%.2f%%)\n", mean, totalBits, 100*mean/float64(blockSize*8))
	fmt.Printf("Desvio padrão: %.2f bits\n", stddev)
	fmt.Printf("Mínimo: %d bits, Máximo: %d bits\n", min, max)
}

// ============ Walsh-Hadamard Spectrum ============

func boolToBit(b bool) int {
	if b {
		return 1
	}
	return -1
}

// Função que realiza a transformada de Walsh-Hadamard para um vetor binário
func walshHadamardTransform(vec []int) []int {
	n := len(vec)
	h := make([]int, n)
	copy(h, vec)

	for len := 1; len < n; len <<= 1 {
		for i := 0; i < n; i += 2 * len {
			for j := 0; j < len; j++ {
				u := h[i+j]
				v := h[i+j+len]
				h[i+j] = u + v
				h[i+j+len] = u - v
			}
		}
	}
	return h
}

func testWalshSpectrum(name string, encryptFunc func([]byte) []byte, blockSize int) {
	fmt.Printf("\n🔍 Espectro Walsh-Hadamard (%s):\n", name)

	numInputs := 1 << 12 // 4096 amostras
	outputBit := 0       // analisando o primeiro bit da saída

	vec := make([]int, numInputs)

	for i := 0; i < numInputs; i++ {
		in := make([]byte, blockSize)
		for j := 0; j < blockSize; j++ {
			if j < 2 {
				in[j] = byte(i >> (8 * (1 - j)) & 0xFF)
			}
		}

		c := encryptFunc(in)
		bit := (c[0] >> outputBit) & 1
		vec[i] = boolToBit(bit == 1)
	}

	spectrum := walshHadamardTransform(vec)

	maxAbs := 0
	for _, v := range spectrum {
		if abs := int(math.Abs(float64(v))); abs > maxAbs {
			maxAbs = abs
		}
	}
	nonlinearity := (numInputs - maxAbs) / 2
	fmt.Printf("🧠 Não-linearidade estimada: %d (máx. possível: %d)\n", nonlinearity, numInputs/2)
}

// ================ LINEAR ================

type LinearTest struct {
	PlainMask  []int
	CipherMask []int
	Trials     int
}

func applyMask(bits []byte, positions []int) byte {
	var result byte
	for _, pos := range positions {
		byteIndex := pos / 8
		bitIndex := pos % 8
		result ^= (bits[byteIndex] >> (7 - bitIndex)) & 1
	}
	return result
}

func LinearApproximation(cipherFunc func([]byte) []byte, test LinearTest) float64 {
	match := 0
	for i := 0; i < test.Trials; i++ {
		pt := randomBytes(16)
		ct := cipherFunc(pt)
		in := applyMask(pt, test.PlainMask)
		out := applyMask(ct, test.CipherMask)
		if in == out {
			match++
		}
	}
	return math.Abs(float64(match)/float64(test.Trials) - 0.5)
}

func LinearAnalysis(cipherFunc func([]byte) []byte, test LinearTest, iterations int) float64 {
	var totalBias float64
	for i := 0; i < iterations; i++ {
		bias := LinearApproximation(cipherFunc, test)
		totalBias += bias
	}
	return totalBias / float64(iterations)
}

// ============ DIFFERENTIAL ==============

func DifferentialAnalysis(cipherFunc func([]byte) []byte, deltaIn []byte, trials int) map[string]int {
	stats := make(map[string]int)
	for i := 0; i < trials; i++ {
		pt1 := randomBytes(16)
		pt2 := xorBytes(pt1, deltaIn)
		ct1 := cipherFunc(pt1)
		ct2 := cipherFunc(pt2)
		deltaOut := xorBytes(ct1, ct2)
		stats[hex.EncodeToString(deltaOut)]++
	}
	return stats
}

func printTopDeltas(stats map[string]float64) {
	total := 0.0
	for _, v := range stats {
		total += v
	}
	fmt.Println("Top 5 deltas:")
	count := 0
	for k, v := range stats {
		fmt.Printf("ΔC: %s → %.5f\n", k, v/total)
		count++
		if count >= 5 {
			break
		}
	}
}

func DifferentialAnalysisWithIterations(cipherFunc func([]byte) []byte, deltaIn []byte, trials int, iterations int) map[string]float64 {
	aggregatedStats := make(map[string]int)
	for i := 0; i < iterations; i++ {
		stats := DifferentialAnalysis(cipherFunc, deltaIn, trials)
		for k, v := range stats {
			aggregatedStats[k] += v
		}
	}

	// Normalize to get average occurrences
	total := 0
	for _, v := range aggregatedStats {
		total += v
	}

	averageStats := make(map[string]float64)
	for k, v := range aggregatedStats {
		averageStats[k] = float64(v) / float64(total)
	}

	return averageStats
}

// ============ PARTIAL BLOCK TESTS ==============

func TestPartialBlocks(cipherFunc func([]byte) []byte) {
	sizes := []int{1, 5, 9, 13}
	for _, size := range sizes {
		pt := make([]byte, size)
		rand.Read(pt)
		padded := padPKCS7(pt, 16)
		ct := cipherFunc(padded)
		fmt.Printf("Input: %d bytes → Ciphertext: %x\n", size, ct)
	}
}

// =============== MAIN ===============

func main() {
	// Linear
	test := LinearTest{
		PlainMask:  []int{0, 5, 9},
		CipherMask: []int{3, 7, 12},
		Trials:     100000,
	}
	iterations := 10 // Defina o número de iterações para a média

	fmt.Println("== Linear Criptoanálise ==")
	biasAES := LinearAnalysis(AESFunc, test, iterations)
	biasGinga := LinearAnalysis(GingaFunc, test, iterations)
	biasLEA := LinearAnalysis(LEAFunc, test, iterations)
	biasSpeck := LinearAnalysis(SpeckFunc, test, iterations)
	fmt.Printf("AES Bias (média):   %.5f\n", biasAES)
	fmt.Printf("Ginga Bias (média): %.5f\n", biasGinga)
	fmt.Printf("LEA Bias (média):   %.5f\n", biasLEA)
	fmt.Printf("Speck Bias (média): %.5f\n", biasSpeck)

	// Diferencial
	fmt.Println("\n== Criptoanálise Diferencial ==")
	delta := make([]byte, 16)
	delta[15] = 0x01
	fmt.Println("AES:")
	printTopDeltas(DifferentialAnalysisWithIterations(AESFunc, delta, 10000, iterations))
	fmt.Println("Ginga:")
	printTopDeltas(DifferentialAnalysisWithIterations(GingaFunc, delta, 10000, iterations))
	fmt.Println("LEA:")
	printTopDeltas(DifferentialAnalysisWithIterations(LEAFunc, delta, 10000, iterations))
	fmt.Println("Speck:")
	printTopDeltas(DifferentialAnalysisWithIterations(SpeckFunc, delta, 10000, iterations))

	// Blocos Parciais
	fmt.Println("\n== Testes com blocos incompletos ==")
	fmt.Println("AES:")
	TestPartialBlocks(AESFunc)
	fmt.Println("Ginga:")
	TestPartialBlocks(GingaFunc)
	fmt.Println("LEA:")
	TestPartialBlocks(LEAFunc)
	fmt.Println("Speck:")
	TestPartialBlocks(SpeckFunc)
	
	aesKey := []byte("0123456789abcdef0123456789abcdef")
	gingaKey := []byte("0123456789abcdef0123456789abcdef")
	leaKey := []byte("0123456789abcdef0123456789abcdef")
	speckKey := []byte("0123456789abcdef0123456789abcdef")

	testBoomerang("AES", AESEncrypt, AESDecrypt, aesKey)
	testBoomerang("Ginga", GingaEncrypt, GingaDecrypt, gingaKey)
	testBoomerang("LEA", LEAEncrypt, LEADecrypt, leaKey)
	testBoomerang("Speck", SpeckEncrypt, SpeckDecrypt, speckKey)
	
	fmt.Println("\n== Chi-Squared ==")
	testChiSquared("AES", AESFunc, 16)
	testChiSquared("Ginga", GingaFunc, 16)
	testChiSquared("LEA", LEAFunc, 16)
	testChiSquared("Speck", SpeckFunc, 16)
	
	fmt.Println("\n== Difusão ==")
	testDiffusion("AES", AESFunc, 16)
	testDiffusion("Ginga", GingaFunc, 16)
	testDiffusion("LEA", LEAFunc, 16)
	testDiffusion("Speck", SpeckFunc, 16)
	
	fmt.Println("\n== Uniformidade dos Bytes ==")
	testByteUniformity("AES", AESFunc, 16)
	testByteUniformity("Ginga", GingaFunc, 16)
	testByteUniformity("LEA", LEAFunc, 16)
	testByteUniformity("Speck", SpeckFunc, 16)
	
	fmt.Println("\n== Teste de Distribuição de Bits ==")
	testBitDistribution("AES", AESFunc, 16)
	testBitDistribution("Ginga", GingaFunc, 16)
	testBitDistribution("LEA", LEAFunc, 16)
	testBitDistribution("Speck", SpeckFunc, 16)
	
	testGlobalAvalanchePlain("AES", AESEncrypt, aesKey, 16)
	testGlobalAvalanchePlain("Ginga", GingaEncrypt, gingaKey, 16)
	testGlobalAvalanchePlain("LEA", LEAEncrypt, leaKey, 16)
	testGlobalAvalanchePlain("Speck", SpeckEncrypt, speckKey, 16)
	
	testWalshSpectrum("AES", AESFunc, 16)
	testWalshSpectrum("Ginga", GingaFunc, 16)
	testWalshSpectrum("LEA", LEAFunc, 16)
	testWalshSpectrum("Speck", SpeckFunc, 16)
}
