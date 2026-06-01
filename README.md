# POLY-NUM: Algoritmo de Cifrado Asimetrico Basado en Numeros Poligonales

Prototipo academico de un algoritmo de cifrado asimetrico experimental basado en
la teoria de numeros poligonales, aplicado a la proteccion de credenciales en
sistemas de autenticacion remota bancaria.

**Autores:**
- Baldarrago Samatelo, Piero
- De los Rios Peralta, Jean Mael
- Guerra Huanaco, Keny Russell
- Sayritupac Asqui, Jeampier

**Institucion:** Escuela Profesional de Ingenieria de Sistemas, UCSM, Arequipa, Peru

---

## Descripcion del algoritmo

### Fundamento matematico

El numero poligonal de tipo `s` en la posicion `n` se define como:

```
P(s, n) = n * [(s-2)*n - (s-4)] / 2       (s >= 3, n >= 1)
```

### Generacion de claves

| Componente    | Descripcion                                           | Visibilidad |
|---------------|-------------------------------------------------------|-------------|
| `s`           | Tipo de poligono, entero en [3, 20]                   | PRIVADA     |
| `k`           | Desplazamiento inicial, entero en [1, 100]            | PRIVADA     |
| `P1`          | Clave publica: `P1 = P(s, 1+k)`                      | PUBLICA     |

Para `s=5`, `k=7`: `P1 = P(5, 8) = 92`

### Cifrado (byte a byte)

```
mask_i = (P1 * (i + 1)) mod 256
C_i    = M_i  XOR  mask_i
```

### Descifrado (propiedad involutiva del XOR)

```
mask_i = (P1 * (i + 1)) mod 256
M_i    = C_i  XOR  mask_i
```

---

## Estructura del proyecto

```
polynumbank/
  src/
    polynum.js    Nucleo matematico del algoritmo
    servidor.js   Servidor HTTP bancario (puerto 3000)
    cliente.js    Aplicacion cliente bancaria
  demo/
    demo.js       Demostracion standalone sin servidor
  test/
    tests.js      Suite de 22 pruebas unitarias
  package.json
  .gitignore
  README.md
```

---

## Requisitos

- Node.js >= 16.0.0
- Sin dependencias externas

---

## Ejecucion

### Demostracion autonoma (sin servidor)

```bash
node demo/demo.js
```

Muestra: secuencias poligonales, generacion de claves, cifrado byte a byte,
descifrado exitoso y simulacion de ataque con clave incorrecta.

### Suite de pruebas (22 casos)

```bash
node test/tests.js
```

Resultado esperado: `[OK] Todos los tests pasaron (22/22) -- cobertura 100%`

### Sistema cliente-servidor completo

Abrir dos terminales:

```bash
# Terminal 1: iniciar servidor bancario
node src/servidor.js

# Terminal 2: ejecutar cliente
node src/cliente.js
```

### Variables de entorno (opcional)

```bash
POLY_S=7 POLY_K=15 PORT=3001 node src/servidor.js
```

---

## Protocolo de autenticacion (5 etapas)

```
Cliente                                    Servidor
  |                                            |
  |  GET /clave-publica                        |
  | ----------------------------------------> |
  |                                            |  Etapa 1: emite P1
  |  { clavePublica: 92 }                      |
  | <---------------------------------------- |
  |                                            |
  |  [Etapa 2] cifrar(password, P1) en LOCAL   |
  |  La contrasena en texto plano NUNCA sale   |
  |  del dispositivo cliente.                  |
  |                                            |
  |  POST /autenticar                          |
  |  { usuario, passwordCifrado: "1ED9..." }   |  Etapa 3: transmision
  | ----------------------------------------> |
  |                                            |  Etapa 4: descifra con (s, k)
  |                                            |  Etapa 5: verifica y emite token
  |  { ok: true, token: "..." }                |
  | <---------------------------------------- |
```

---

## Propiedades de seguridad

| Propiedad             | Estado en v1.1     | Observacion                                |
|-----------------------|--------------------|--------------------------------------------|
| Asimetria             | Funcional          | Basada en ecuacion diofantica cuadratica   |
| Confidencialidad      | Bajo modelo Dolev-Yao | Sin (s,k) el cifrado es ininteligible  |
| Resistencia frecuencias | Parcial          | Mascara posicional, periodo T=64 (P1=92)   |
| IND-CPA               | NO cumple          | Cifrado deterministico sin nonce           |
| Espacio de claves     | ~11 bits (demo)    | ~50 bits en configuracion extendida        |

---

## Limitaciones documentadas

1. **Sin nonce aleatorio:** el cifrado es deterministico. La misma contrasena
   con la misma `P1` siempre produce el mismo texto cifrado. No cumple IND-CPA.

2. **Periodicidad de la mascara:** `T = 256 / MCD(P1, 256)`. Para `P1=92`,
   `T=64`. No representa vulnerabilidad para contrasenas bancarias tipicas
   (< 20 bytes), pero si para mensajes mas largos.

3. **Espacio de claves reducido en demostracion:** con `s` en `[3,20]` y
   `k` en `[1,100]`, el espacio de 1800 combinaciones (~11 bits) es atacable
   por fuerza bruta. Solo para uso academico.

---

## Hoja de ruta v2.0

- Incorporar nonce aleatorio de 128 bits por sesion
- Derivar mascara con `mask_i = SHA-256(P1 || nonce || i) mod 256`
- Extender rangos de `s` y `k` a representacion de multiprecision (>= 128 bits)
- Evaluacion formal IND-CPA e IND-CCA bajo modelo de oraculo aleatorio

---

## Referencias

- Rivest, Shamir, Adleman. "A method for obtaining digital signatures and
  public-key cryptosystems." CACM, 1978.
- Schneier, B. "Applied Cryptography." Wiley, 2015.
- NIST SP 800-63B. "Digital Identity Guidelines." 2017.
- Dolev, D.; Yao, A. "On the security of public key protocols." IEEE TIT, 1983.
- Bellare, M.; Rogaway, P. "Optimal Asymmetric Encryption." EUROCRYPT, 1994.

---

**Aviso:** Este software es un prototipo de investigacion academica.
No debe usarse en sistemas de produccion sin incorporar las mejoras
de seguridad descritas en la hoja de ruta v2.0.
