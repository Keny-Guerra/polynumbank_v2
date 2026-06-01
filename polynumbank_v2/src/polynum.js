'use strict';

/**
 * @fileoverview polynum.js — Nucleo matematico del algoritmo POLY-NUM v1.1
 *
 * POLY-NUM: Algoritmo de Cifrado Asimetrico Basado en Numeros Poligonales
 * para la Proteccion de Credenciales en Sistemas de Autenticacion Remota Bancaria.
 *
 * FUNDAMENTO MATEMATICO
 *   Numero poligonal:  P(s, n) = n * [(s-2)*n - (s-4)] / 2
 *     s  entero >= 3  : tipo de poligono (clave privada, componente 1)
 *     k  entero >= 1  : desplazamiento   (clave privada, componente 2)
 *     P1 = P(s, 1+k)  : clave publica    (unico valor compartido con el cliente)
 *
 * ESQUEMA DE CIFRADO (por byte, posicion i)
 *   mask_i = (P1 * (i + 1)) mod 256
 *   C_i    = M_i  XOR  mask_i
 *
 * ESQUEMA DE DESCIFRADO (propiedad involutiva del XOR: a XOR b XOR b = a)
 *   M_i    = C_i  XOR  mask_i
 *
 * LIMITACIONES DOCUMENTADAS (version prototipo)
 *   1. Sin relleno aleatorio (nonce): el cifrado es deterministico y no
 *      satisface IND-CPA. Misma contrasena con misma P1 produce siempre
 *      el mismo texto cifrado.
 *   2. Periodicidad de mascara: T = 256 / MCD(P1, 256). Para contraseñas
 *      bancarias tipicas (< 20 bytes) no representa vulnerabilidad practica,
 *      pero si para mensajes largos.
 *   3. Espacio de claves reducido en configuracion de demostracion
 *      (s en [3,20], k en [1,100] => 1800 combinaciones ~ 11 bits).
 *
 * @version 1.1.0
 * @authors Baldarrago Samatelo, Piero
 *          De los Rios Peralta, Jean Mael
 *          Guerra Huanaco, Keny Russell
 *          Sayritupac, Asqui Jeampier
 * @institution Escuela Profesional de Ingenieria de Sistemas — UCSM, Arequipa, Peru
 * @license MIT
 */

// ---------------------------------------------------------------------------
//  CONSTANTES DE CONFIGURACION
// ---------------------------------------------------------------------------

const S_MIN          = 3;     // Tipo de poligono minimo (triangulo)
const S_MAX          = 20;    // Tipo de poligono maximo (demostracion)
const K_MIN          = 1;     // Desplazamiento minimo
const K_MAX          = 100;   // Desplazamiento maximo (demostracion)
const MODULO_MASCARA = 256;   // Modulo del byte (2^8)

// ---------------------------------------------------------------------------
//  FUNCION BASE: NUMERO POLIGONAL P(s, n)
// ---------------------------------------------------------------------------

/**
 * Calcula el n-esimo numero poligonal de tipo s.
 *
 * Formula general (valida para s >= 3, n >= 1):
 *   P(s, n) = n * [(s-2)*n - (s-4)] / 2
 *
 * Secuencias canonicas:
 *   s=3 -> triangulares  {1, 3, 6, 10, 15, 21, ...}
 *   s=4 -> cuadrados     {1, 4, 9, 16, 25, 36, ...}
 *   s=5 -> pentagonales  {1, 5, 12, 22, 35, 51, ...}
 *   s=6 -> hexagonales   {1, 6, 15, 28, 45, 66, ...}
 *
 * El resultado siempre es entero porque n*[(s-2)*n-(s-4)] es par para
 * todo entero n y todo entero s >= 3.
 *
 * @param {number} s - Tipo de poligono (entero >= S_MIN).
 * @param {number} n - Indice del termino (entero >= 1).
 * @returns {number} n-esimo numero poligonal de tipo s.
 * @throws {TypeError}  Si s o n no son enteros.
 * @throws {RangeError} Si s < S_MIN o n < 1.
 */
function polyNum(s, n) {
  if (!Number.isInteger(s) || !Number.isInteger(n)) {
    throw new TypeError(
      'polyNum: s y n deben ser numeros enteros. ' +
      `Recibidos: s=${s} (${typeof s}), n=${n} (${typeof n})`
    );
  }
  if (s < S_MIN) {
    throw new RangeError(
      `polyNum: s debe ser >= ${S_MIN} (minimo: triangulo). Recibido: s=${s}`
    );
  }
  if (n < 1) {
    throw new RangeError(
      `polyNum: n debe ser >= 1. Recibido: n=${n}`
    );
  }
  return (n * ((s - 2) * n - (s - 4))) / 2;
}

// ---------------------------------------------------------------------------
//  UTILIDADES MATEMATICAS
// ---------------------------------------------------------------------------

/**
 * Calcula el Maximo Comun Divisor de dos enteros no negativos
 * mediante el algoritmo de Euclides iterativo.
 *
 * @param {number} a - Primer entero no negativo.
 * @param {number} b - Segundo entero no negativo.
 * @returns {number} MCD(a, b).
 */
function mcd(a, b) {
  while (b !== 0) {
    [a, b] = [b, a % b];
  }
  return a;
}

/**
 * Calcula el periodo de la secuencia de mascaras posicionales para una
 * clave publica dada.
 *
 *   T = MODULO_MASCARA / MCD(P1, MODULO_MASCARA)
 *
 * Interpretacion: los bytes del mensaje en posiciones i e i+T producen
 * mascaras identicas. Para contraseñas bancarias tipicas (longitud < 20
 * bytes) con T=64 (cuando P1=92), esto no representa vulnerabilidad
 * practica.
 *
 * @param {number} p1 - Clave publica (entero positivo).
 * @returns {number} Periodo T de la secuencia de mascaras.
 */
function periodoCicloMascara(p1) {
  return MODULO_MASCARA / mcd(p1, MODULO_MASCARA);
}

// ---------------------------------------------------------------------------
//  GENERACION DE CLAVES
// ---------------------------------------------------------------------------

/**
 * Genera el par de claves POLY-NUM a partir de los parametros privados.
 *
 * El servidor bancario genera (s, k), calcula P1 = P(s, 1+k) y publica
 * unicamente P1. El cliente cifra su contrasena usando P1; jamas conoce
 * s ni k.
 *
 * Nota sobre colisiones:
 *   En el rango s=[3,20], k=[1,100] existen 127 colisiones conocidas
 *   (pares distintos (s,k) con el mismo P1). Esto reduce la entropia
 *   efectiva de 10.81 bits teoricos a ~10.70 bits reales. No representa
 *   una vulnerabilidad de autenticacion ya que el servidor siempre descifra
 *   con su propio par (s, k).
 *
 * @param {number} s - Tipo de poligono. Entero en [S_MIN, S_MAX].
 * @param {number} k - Desplazamiento inicial. Entero en [K_MIN, K_MAX].
 * @returns {{
 *   clavePublica:     number,
 *   clavePrivada:     {s: number, k: number},
 *   periodo:          number,
 *   bitsEquivalentes: string
 * }}
 * @throws {TypeError}  Si s o k no son enteros.
 * @throws {RangeError} Si s o k estan fuera de los rangos definidos.
 */
function generarClaves(s, k) {
  if (!Number.isInteger(s)) {
    throw new TypeError(
      `generarClaves: s debe ser un entero. Recibido: ${s} (${typeof s})`
    );
  }
  if (!Number.isInteger(k)) {
    throw new TypeError(
      `generarClaves: k debe ser un entero. Recibido: ${k} (${typeof k})`
    );
  }
  if (s < S_MIN || s > S_MAX) {
    throw new RangeError(
      `generarClaves: s debe estar en [${S_MIN}, ${S_MAX}]. Recibido: ${s}`
    );
  }
  if (k < K_MIN || k > K_MAX) {
    throw new RangeError(
      `generarClaves: k debe estar en [${K_MIN}, ${K_MAX}]. Recibido: ${k}`
    );
  }

  const clavePublica     = polyNum(s, 1 + k);
  const clavePrivada     = { s, k };
  const periodo          = periodoCicloMascara(clavePublica);
  const espacioTotal     = (S_MAX - S_MIN + 1) * (K_MAX - K_MIN + 1);
  const bitsEquivalentes = Math.log2(espacioTotal).toFixed(2);

  return { clavePublica, clavePrivada, periodo, bitsEquivalentes };
}

// ---------------------------------------------------------------------------
//  ALGORITMO DE CIFRADO
// ---------------------------------------------------------------------------

/**
 * Cifra un mensaje de texto usando la clave publica P1 (algoritmo POLY-NUM).
 *
 * Para cada posicion i en {0, 1, ..., longitud-1}:
 *   mask_i = (P1 * (i + 1)) mod 256
 *   C_i    = M_i  XOR  mask_i
 *
 * La dependencia lineal de mask_i con la posicion garantiza que bytes
 * identicos en posiciones distintas produzcan cifrados distintos,
 * mitigando ataques de analisis de frecuencias para contraseñas cortas.
 *
 * ADVERTENCIA: Este cifrado es deterministico. La misma contrasena con
 * la misma P1 siempre produce el mismo texto cifrado. No cumple IND-CPA.
 * Usar exclusivamente en el contexto academico descrito en el paper.
 *
 * @param {string} texto        - Mensaje a cifrar (codificacion UTF-8).
 * @param {number} clavePublica - Clave publica P1 (entero positivo).
 * @returns {{
 *   cifrado:  string,    // Texto cifrado en hexadecimal (mayusculas)
 *   mascaras: number[],  // Mascaras posicionales aplicadas [mask_0, ..., mask_{l-1}]
 *   longitud: number,    // Longitud en bytes del mensaje original
 *   periodo:  number     // Periodo de la secuencia de mascaras
 * }}
 * @throws {TypeError}  Si texto no es string o clavePublica no es entero.
 * @throws {RangeError} Si texto esta vacio o clavePublica <= 0.
 */
function cifrar(texto, clavePublica) {
  if (typeof texto !== 'string') {
    throw new TypeError(
      `cifrar: texto debe ser un string. Recibido: ${typeof texto}`
    );
  }
  if (texto.length === 0) {
    throw new RangeError('cifrar: el texto no puede estar vacio');
  }
  if (!Number.isInteger(clavePublica)) {
    throw new TypeError(
      `cifrar: clavePublica debe ser un entero. Recibido: ${clavePublica}`
    );
  }
  if (clavePublica <= 0) {
    throw new RangeError(
      `cifrar: clavePublica debe ser un entero positivo. Recibido: ${clavePublica}`
    );
  }

  const bytes    = Buffer.from(texto, 'utf8');
  const cifrado  = Buffer.alloc(bytes.length);
  const mascaras = [];

  for (let i = 0; i < bytes.length; i++) {
    const mascara = (clavePublica * (i + 1)) % MODULO_MASCARA;
    mascaras.push(mascara);
    cifrado[i] = bytes[i] ^ mascara;
  }

  return {
    cifrado  : cifrado.toString('hex').toUpperCase(),
    mascaras,
    longitud : bytes.length,
    periodo  : periodoCicloMascara(clavePublica)
  };
}

// ---------------------------------------------------------------------------
//  ALGORITMO DE DESCIFRADO
// ---------------------------------------------------------------------------

/**
 * Descifra un texto cifrado (hexadecimal) usando la clave privada (s, k).
 *
 * El servidor reconstruye P1 = P(s, 1+k) y aplica la misma mascara
 * posicional. Por la propiedad involutiva del XOR (a XOR b XOR b = a):
 *   M_i = C_i  XOR  mask_i
 *
 * El descifrado produce el mensaje original si y solo si P1 reconstruida
 * desde (s, k) coincide con la empleada durante el cifrado. Con cualquier
 * otro par (s', k'), el resultado es una cadena ininteligible.
 *
 * @param {string}               hexCifrado   - Texto cifrado en hexadecimal.
 * @param {{s: number, k: number}} clavePrivada - Parametros privados del servidor.
 * @returns {string} Texto descifrado en codificacion UTF-8.
 * @throws {TypeError}  Si hexCifrado no es string o contiene caracteres no hexadecimales.
 * @throws {RangeError} Si hexCifrado esta vacio o tiene longitud impar.
 */
function descifrar(hexCifrado, clavePrivada) {
  if (typeof hexCifrado !== 'string') {
    throw new TypeError(
      `descifrar: hexCifrado debe ser un string. Recibido: ${typeof hexCifrado}`
    );
  }
  if (hexCifrado.length === 0) {
    throw new RangeError('descifrar: hexCifrado no puede estar vacio');
  }
  if (hexCifrado.length % 2 !== 0) {
    throw new RangeError(
      'descifrar: hexCifrado debe tener longitud par (representacion hexadecimal completa)'
    );
  }
  if (!/^[0-9a-fA-F]+$/.test(hexCifrado)) {
    throw new TypeError(
      'descifrar: hexCifrado contiene caracteres no hexadecimales'
    );
  }

  const { s, k } = clavePrivada;
  if (!Number.isInteger(s) || !Number.isInteger(k)) {
    throw new TypeError(
      'descifrar: clavePrivada.s y clavePrivada.k deben ser enteros'
    );
  }

  const p1Reconstruida = polyNum(s, 1 + k);
  const bytes          = Buffer.from(hexCifrado, 'hex');
  const resultado      = Buffer.alloc(bytes.length);

  for (let i = 0; i < bytes.length; i++) {
    const mascara  = (p1Reconstruida * (i + 1)) % MODULO_MASCARA;
    resultado[i]   = bytes[i] ^ mascara;
  }

  return resultado.toString('utf8');
}

// ---------------------------------------------------------------------------
//  VERIFICACION DE CLAVE PUBLICA
// ---------------------------------------------------------------------------

/**
 * Verifica que la clave publica recibida del cliente coincide con la
 * clave publica generada por el servidor a partir de (s, k).
 *
 * Permite al servidor detectar intentos de suplantacion en los que
 * un cliente presenta una P1 distinta a la emitida.
 *
 * @param {number}               p1Recibida  - Clave publica reportada por el cliente.
 * @param {{s: number, k: number}} clavePrivada - Parametros privados del servidor.
 * @returns {boolean} true si P1 coincide con P(s, 1+k); false en caso contrario.
 */
function verificarClavePublica(p1Recibida, clavePrivada) {
  if (!Number.isInteger(p1Recibida)) return false;
  try {
    const p1Esperada = polyNum(clavePrivada.s, 1 + clavePrivada.k);
    return p1Recibida === p1Esperada;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
//  DIAGNOSTICO DE PROPIEDADES CRIPTOGRAFICAS
// ---------------------------------------------------------------------------

/**
 * Genera un reporte de las propiedades criptograficas del esquema
 * para una configuracion de claves dada. Uso exclusivo para analisis
 * academico y depuracion.
 *
 * @param {number} s - Tipo de poligono.
 * @param {number} k - Desplazamiento.
 * @returns {{
 *   p1:               number,
 *   periodo:          number,
 *   espacioTotal:     number,
 *   bitsEquivalentes: string,
 *   advertencias:     string[]
 * }}
 */
function diagnosticar(s, k) {
  const { clavePublica } = generarClaves(s, k);
  const periodo          = periodoCicloMascara(clavePublica);
  const espacioTotal     = (S_MAX - S_MIN + 1) * (K_MAX - K_MIN + 1);
  const advertencias     = [];

  if (periodo < 20) {
    advertencias.push(
      `[WARN] Periodo corto (T=${periodo} bytes). ` +
      `Contrasenas de mas de ${periodo} bytes son vulnerables a analisis de mascara.`
    );
  }
  if (espacioTotal < 100000) {
    advertencias.push(
      `[WARN] Espacio de claves reducido: ${espacioTotal} combinaciones ` +
      `(${Math.log2(espacioTotal).toFixed(1)} bits). Solo apto para demostracion academica.`
    );
  }
  advertencias.push(
    '[INFO] Cifrado DETERMINISTICO (sin nonce). No cumple IND-CPA. ' +
    'No usar en produccion sin incorporar nonce y derivacion de mascara via SHA-256.'
  );

  return {
    p1               : clavePublica,
    periodo,
    espacioTotal,
    bitsEquivalentes : Math.log2(espacioTotal).toFixed(2),
    advertencias
  };
}

// ---------------------------------------------------------------------------
//  EXPORTACIONES
// ---------------------------------------------------------------------------

module.exports = {
  polyNum,
  mcd,
  periodoCicloMascara,
  generarClaves,
  cifrar,
  descifrar,
  verificarClavePublica,
  diagnosticar,
  constantes: { S_MIN, S_MAX, K_MIN, K_MAX, MODULO_MASCARA }
};
