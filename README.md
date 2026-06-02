# POLY-NUM: Algoritmo de Cifrado Asimetrico Basado en Numeros Poligonales

Prototipo academico de un algoritmo de cifrado asimetrico experimental
basado en la teoria de numeros poligonales, aplicado a la proteccion
de credenciales en sistemas de autenticacion remota bancaria.

**Autores**
- Baldarrago Samatelo, Piero
- De los Rios Peralta, Jean Mael
- Guerra Huanaco, Keny Russell
- Sayritupac, Asqui Jeampier

**Institucion:** Escuela Profesional de Ingenieria de Sistemas, UCSM, Arequipa, Peru

---

## Requisitos

- Node.js >= 16.0.0
- Sin dependencias externas (solo modulos nativos de Node.js)

Verificar instalacion:
```bash
node --version
```

---

## Instalacion

```bash
git clone https://github.com/Keny-Guerra/polynumbank_v2.git
cd polynumbank_v2
```

No se requiere `npm install`. El proyecto no tiene dependencias externas.

---

## Estructura del proyecto

```
polynumbank_v2/
  src/
    polynum.js               Nucleo matematico del algoritmo POLY-NUM
    servidor.js              Servidor HTTP bancario (puerto 3000)
    cliente.js               Cliente HTTP de demostracion
  demo/
    demo.js                  Demostracion autonoma (sin servidor)
    cifrado_credenciales.js  Visualizador interactivo de cifrado
  test/
    tests.js                 Suite de 22 pruebas unitarias
  cliente_web/
    index.html               Interfaz web de inicio de sesion
  package.json
  README.md
```

---

## Formas de ejecutar

Todos los comandos se ejecutan desde la **raiz del proyecto**:

```bash
cd polynumbank_v2
```

---

### 1. Visualizador interactivo de cifrado (recomendado para demo)

Ingresa cualquier usuario y contrasena y muestra el proceso de
cifrado POLY-NUM detalle a detalle en el terminal.

```bash
node demo/cifrado_credenciales.js
```

El programa pide usuario y contrasena y muestra:

- Calculo paso a paso de la clave publica P1
- Tabla byte a byte con: caracter, ASCII, mascara, operacion XOR y hex
- La secuencia completa de mascaras posicionales
- El texto cifrado final que viajaria por la red
- Verificacion del descifrado byte a byte

---

### 2. Demostracion autonoma del algoritmo

```bash
node demo/demo.js
```

Muestra sin necesitar servidor:

- Secuencias poligonales triangulares, cuadradas, pentagonales y hexagonales
- Generacion de claves con diagnostico de seguridad
- Cifrado byte a byte de la credencial `Banc@2024` con P1=92
- Descifrado exitoso en el servidor
- Simulacion de ataque con clave incorrecta (resultado ininteligible)
- Analisis del periodo T de la mascara

---

### 3. Suite de pruebas unitarias (22 casos)

```bash
node test/tests.js
```

Resultado esperado:

```
[OK] Todos los tests pasaron (22/22) -- cobertura 100%
```

Los 22 casos cubren seis grupos:

| Grupo | Descripcion | Casos |
|-------|-------------|-------|
| 1 | Correctitud de la formula poligonal | 5 |
| 2 | Generacion de claves y validaciones | 5 |
| 3 | Ciclos cifrado / descifrado | 6 |
| 4 | Verificacion de clave publica | 2 |
| 5 | Analisis matematico del esquema | 2 |
| 6 | Manejo de errores y entradas invalidas | 2 |

---

### 4. Sistema cliente-servidor completo con interfaz web

**Paso 1:** Iniciar el servidor (Terminal 1)

```bash
node src/servidor.js
```

El servidor muestra en consola el proceso completo de cifrado y descifrado
cada vez que un usuario inicia sesion.

**Paso 2:** Abrir la interfaz web

Abre el archivo `cliente_web/index.html` directamente en el navegador
(doble clic o arrastrarlo al navegador).

**Paso 3:** Iniciar sesion con los usuarios de demostracion

| Usuario  | Contrasena  | Resultado esperado |
|----------|-------------|-------------------|
| jperez   | Banc@2024   | Token de sesion   |
| mgarcia  | Seguro#99   | Token de sesion   |
| admin    | Admin!2025  | Token de sesion   |

Al hacer login, el **terminal del servidor** muestra automaticamente:

```
================================================================
  PROCESO DE AUTENTICACION POLY-NUM
================================================================
  Usuario           : jperez
  Hex recibido      : 1ED97A138C1AB4D208

  [Etapa 1] Clave publica entregada al cliente: P1 = 92
  [Etapa 2] El cliente cifro localmente (texto plano nunca viajo)
  [Etapa 3] Datos recibidos via POST /autenticar
  [Etapa 4] Descifrado byte a byte:

   Pos    Hex    Dec   Mascara   XOR   Char
    1      1E     30      92      66    "B"
    2      D9    217     184      97    "a"
    3      7A    122      20     110    "n"
    ...

  [Etapa 5] Coinciden: SI  ->  AUTENTICADO HTTP 200
================================================================
```

**Paso 4 (opcional):** Ejecutar el cliente HTTP en vez de la web

```bash
node src/cliente.js
```

---

### 5. Parametros configurables

```bash
POLY_S=7 POLY_K=15 PORT=3001 node src/servidor.js
```

| Variable | Descripcion | Default |
|----------|-------------|---------|
| POLY_S | Tipo de poligono s (clave privada) | 5 |
| POLY_K | Desplazamiento k (clave privada) | 7 |
| PORT | Puerto HTTP del servidor | 3000 |

---

## Como funciona el algoritmo

### Fundamento matematico

El numero poligonal de tipo `s` en la posicion `n`:

```
P(s, n) = n * [(s-2)*n - (s-4)] / 2       s >= 3,  n >= 1
```

Ejemplo con s=5, k=7:

```
P1 = P(5, 1+7) = P(5, 8)
   = 8 * [(5-2)*8 - (5-4)] / 2
   = 8 * [24 - 1] / 2
   = 8 * 23 / 2
   = 92
```

### Claves

| Componente | Valor ejemplo | Quien lo conoce |
|------------|---------------|-----------------|
| s = 5      | tipo pentagonal | Solo el servidor |
| k = 7      | desplazamiento  | Solo el servidor |
| P1 = 92    | P(5, 1+7)      | Todos (publico)  |

### Cifrado byte a byte

```
mask_i = (P1 * (i+1)) mod 256
C_i    = M_i  XOR  mask_i
```

Ejemplo con "Banc@2024" y P1=92:

```
Pos  Char  ASCII  Mascara  XOR  Hex
  1    B      66      92    30   1E
  2    a      97     184   217   D9
  3    n     110      20   122   7A
  4    c      99     112    19   13
  5    @      64     204   140   8C
  6    2      50      40    26   1A
  7    0      48     132   180   B4
  8    2      50     224   210   D2
  9    4      52      60     8   08

Texto cifrado: 1ED97A138C1AB4D208
```

### Descifrado (propiedad involutiva del XOR)

```
mask_i = (P1 * (i+1)) mod 256
M_i    = C_i  XOR  mask_i

Razon: C XOR mask XOR mask = C XOR 0 = C
```

### Protocolo de autenticacion (5 etapas)

```
Cliente                              Servidor
  |                                      |
  |  GET /clave-publica                  |
  | ----------------------------------> |   Etapa 1
  |  { clavePublica: 92 }               |
  | <---------------------------------- |
  |                                      |
  |  cifrar(password, 92)  [LOCAL]       |   Etapa 2
  |  password nunca sale del dispositivo |
  |                                      |
  |  POST /autenticar                    |
  |  { usuario, passwordCifrado: hex }   |
  | ----------------------------------> |   Etapa 3
  |                                      |
  |                    descifrar(hex, s,k)|  Etapa 4
  |                    verificar en BD   |
  |                                      |
  |  { ok: true, token: "..." }          |
  | <---------------------------------- |   Etapa 5
```

---

## Propiedades de seguridad

| Propiedad | Estado v1.1 | Observacion |
|-----------|-------------|-------------|
| Asimetria | Funcional | Ecuacion diofantica cuadratica |
| Confidencialidad | Bajo modelo Dolev-Yao | Sin (s,k) el cifrado es ininteligible |
| Resistencia frecuencias | Parcial | Mascara posicional, periodo T=64 para P1=92 |
| IND-CPA | No cumple | Cifrado deterministico sin nonce |
| Espacio de claves | ~11 bits (demo) | ~50 bits en configuracion extendida |

---

## Limitaciones documentadas

1. **Sin nonce aleatorio:** la misma contrasena con la misma P1 siempre
   produce el mismo cifrado. No cumple IND-CPA.

2. **Periodicidad de la mascara:** T = 256 / MCD(P1, 256). Para P1=92,
   T=64 bytes. No es vulnerable para contrasenas bancarias tipicas
   (menos de 20 bytes), pero si para mensajes largos.

3. **Espacio de claves reducido en demostracion:** con s en [3,20] y
   k en [1,100] hay 1800 combinaciones (~11 bits). Solo para uso academico.

---

## Hoja de ruta v2.0

- Incorporar nonce aleatorio de 128 bits por sesion
- Derivar mascara con `mask_i = SHA-256(P1 || nonce || i) mod 256`
- Extender rangos de s y k a multiprecision para >= 128 bits de seguridad
- Evaluacion formal IND-CPA e IND-CCA bajo modelo de oraculo aleatorio

---

## Referencias

- Rivest, Shamir, Adleman. "A method for obtaining digital signatures and
  public-key cryptosystems." CACM, vol.21, no.2, pp.120-126, 1978.
- Schneier, B. "Applied Cryptography: Protocols, Algorithms and Source
  Code in C." Wiley, 20th Anniversary Edition, 2015.
- Dolev, D.; Yao, A. "On the security of public key protocols."
  IEEE Transactions on Information Theory, vol.29, no.2, 1983.
- Bellare, M.; Rogaway, P. "Optimal Asymmetric Encryption."
  EUROCRYPT 1994, LNCS vol.950, pp.92-111.
- NIST SP 800-63B. "Digital Identity Guidelines: Authentication and
  Lifecycle Management." 2017.

---

> **Aviso:** Este software es un prototipo de investigacion academica.
> No usar en produccion sin incorporar las mejoras de la hoja de ruta v2.0.
