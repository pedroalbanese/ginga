# Ginga
Ginga Lightweight Block Cipher & Hash Function ARX-based

A cifra de bloco Ginga é um algoritmo experimental de criptografia baseado na estrutura ARX (Addition-Rotation-XOR), operando sobre blocos de 128 bits divididos em 4 palavras de 32 bits ao longo de 16 rodadas. Seu projeto foca em simplicidade e eficiência, utilizando apenas operações aritméticas e lógicas leves para proporcionar confusão e difusão dos dados. Inspirada na fluidez e imprevisibilidade da ginga na capoeira, a cifra aplica rotações dinâmicas e combinações não lineares para obscurecer relações entre chave, texto claro e texto cifrado. Por ser experimental, Ginga não deve ser utilizada em aplicações críticas de segurança, mas sim para fins educacionais, testes e pesquisa em criptografia baseada em ARX.

"[*É um jogo, é uma dança, é uma briga..*](https://www.youtube.com/watch?v=HIkElHAC-1M)" - Paulo César Pinheiro — Capoeira de Besouro

## 🌀 O que é Ginga na Capoeira?

Na capoeira, a **ginga** é o movimento fundamental e contínuo que o praticante realiza com o corpo, principalmente as pernas, quadris e braços.  
Mas ela não é só um passo — é uma *dança estratégica*. Aqui está o que ela representa:

- 🔁 **Movimento constante**: a ginga evita que o capoeirista fique parado e previsível.  
- 🎭 **Confundir o adversário**: com deslocamentos ritmados e corpo solto, é possível esconder a intenção real (ataque ou defesa).  
- 🔄 **Rotação e esquiva**: envolve giros, mudanças de base e direção, dificultando golpes diretos.  
- 🧠 **Desestabilização mental**: a incerteza do próximo movimento confunde o oponente.

## 🔐 Descrição Matemática do Algoritmo

O algoritmo Ginga é uma cifra de bloco baseada em operações **ARX** (Addition, Rotation, XOR), com as seguintes definições:

- **Tamanho do bloco:** $16$ bytes  
- **Mensagem de entrada:** $P = (p_0, p_1, \dots, p_{15}) \in \mathbb{F}_{2^8}^{16}$  
- **Chave:** $K = (k_0, k_1, \dots, k_{31}) \in \mathbb{F}_{2^8}^{32}$  
- **Número de rodadas:** $R = 16$  

### 1. 🧩 Geração de Subchave

Para cada palavra da chave em cada rodada:

$$
k_{r,i} = \text{ROTL}\left(k_{(i + r) \bmod 8} \oplus (73i + 91r),\ (r + i) \bmod 32\right)
$$

onde $\text{ROTL}(x, n)$ é a rotação à esquerda de $x$ por $n$ bits em 32 bits.

---

### 2. 🔄 Função de Confusão

Confusão de 1 passo:

$$
\text{confuse}(x) = \text{ROTL}( (x \oplus \text{0xA5A5A5A5}) + \text{0x3C3C3C3C},\ 7 )
$$

---

### 3. 🔁 Função de Rodada

Cada palavra do estado sofre a seguinte transformação:

$$
\begin{aligned}
x' &= x + k \\
x' &= \text{confuse}(x') \\
x' &= \text{ROTL}(x',\ (r + 3) \bmod 32) \\
x' &= x' \oplus k \\
x' &= \text{ROTL}(x',\ (r + 5) \bmod 32)
\end{aligned}
$$

Logo:

$$
\text{round}(x, k, r) = \text{ROTL}\left( \left( \text{ROTL}(\text{confuse}(x + k),\ (r+3) \bmod 32) \oplus k \right),\ (r+5) \bmod 32 \right)
$$

---

### 4. 🔃 Mistura de Estado (Difusão)

Depois de processar todas as palavras com `round`, aplica-se a difusão no vetor de estado $S = (s_0, \dots, s_3)$:

$$
\begin{aligned}
s_0 &\leftarrow s_0 \oplus \text{ROTL}(s_1,\ 5) \\
s_1 &\leftarrow s_1 \oplus \text{ROTL}(s_2,\ 11) \\
s_2 &\leftarrow s_2 \oplus \text{ROTL}(s_3,\ 17) \\
s_3 &\leftarrow s_3 \oplus \text{ROTL}(s_0,\ 23)
\end{aligned}
$$

---

### 5. 🔓 Operações de Desfazer

A função inversa `invRound` reverte a função `round`, na ordem contrária:

$$
\begin{aligned}
x' &= \text{ROTR}(x,\ (r+5) \bmod 32) \\
x' &= x' \oplus k \\
x' &= \text{ROTR}(x',\ (r+3) \bmod 32) \\
x' &= \text{deconfuse}(x') \\
x' &= x' - k
\end{aligned}
$$

---

### 6. 🔁 Estrutura Geral da Cifra

A cifra completa aplica as rodadas de substituição e mistura em sequência:

Para cada rodada $r = 0, 1, \dots, R-1$:

$$
S_i \leftarrow \text{round}(S_i,\ k_{r,i},\ r), \quad \text{para } i = 0, \dots, 3
$$

Seguido de:

$$
S \leftarrow \text{mixState}(S)
$$

A cifra resulta em $C = S$ após $R$ rodadas.

## Melhores Resultados em Testes Comparativos

- [Ginga Block Cipher](https://go.dev/play/p/bQvEQBAqJKi)
- [AES Block Cipher](https://go.dev/play/p/qqIrQRLwcB-)
- [GingaHash vs. SHA256](https://go.dev/play/p/KcfIN5qZF0a)

## ⚠️ Aviso!

Este algoritmo é fornecido **exclusivamente para fins educacionais e de pesquisa**.

- **Não utilize em produção.**
- Não há garantias de segurança ou resistência contra ataques criptográficos modernos.
- Use algoritmos padronizados e amplamente analisados para aplicações reais.

Este projeto tem o objetivo de aprendizado e experimentação com construção de primitivas criptográficas.

## Contribua
**Use _issues_ para tudo**
- Você pode ajudar e receber ajuda por meio de:
  - Relato de dúvidas e perguntas
- Você pode contribuir por meio de:
  - Relato de problemas (_issues_)
  - Sugestão de novos recursos ou melhorias
  - Aprimoramento ou correção da documentação

## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2025 Pedro F. Albanese - ALBANESE Research Lab.  
Todos os direitos de propriedade intelectual sobre este software pertencem ao autor, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.
