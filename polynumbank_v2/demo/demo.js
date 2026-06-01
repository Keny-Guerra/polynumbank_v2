'use strict';

/**
 * @fileoverview demo.js — Demostracion completa del algoritmo POLY-NUM
 *
 * Demostracion autonoma (sin servidor) que cubre todos los aspectos
 * del algoritmo descritos en el paper academico:
 *
 *   Seccion 1 — Secuencias poligonales de referencia
 *   Seccion 2 — Generacion de claves con diagnostico de seguridad
 *   Seccion 3 — Cifrado byte a byte con tabla detallada
 *   Seccion 4 — Descifrado en el servidor bancario
 *   Seccion 5 — Simulacion de ataque con clave privada incorrecta
 *   Seccion 6 — Analisis de periodicidad de la mascara
 *
 * Ejecutar: node demo/demo.js
 *
 * @version 1.1.0
 * @authors Baldarrago Samatelo, Piero
 *          De los Rios Peralta, Jean Mael
 *          Guerra Huanaco, Keny Russell
 *          Sayritupac, Asqui Jeampier
 * @institution Escuela Profesional de Ingenieria de Sistemas — UCSM
 */

const {
  polyNum,
  generarClaves,
  cifrar,
  descifrar,
  mcd,
  periodoCicloMascara,
  diagnosticar
} = require('../src/polynum');

// ---------------------------------------------------------------------------
//  BANNER
// ---------------------------------------------------------------------------

console.log('');
console.log('+========================================================+');
console.log('|   DEMO POLY-NUM v1.1  --  Cifrado Asimetrico           |');
console.log('|   Aplicacion: Credenciales de Banca en Linea           |');
console.log('|   Escuela de Ingenieria de Sistemas  --  UCSM          |');
console.log('+========================================================+');

// ---------------------------------------------------------------------------
//  SECCION 1: SECUENCIAS POLIGONALES DE REFERENCIA
// ---------------------------------------------------------------------------

console.log('');
console.log('--- Seccion 1: Numeros poligonales (primeros 6 terminos) ---');
console.log('');

const TIPOS_POLIGONO = [
  { s: 3, nombre: 'Triangulares' },
  { s: 4, nombre: 'Cuadrados   ' },
  { s: 5, nombre: 'Pentagonales' },
  { s: 6, nombre: 'Hexagonales ' }
];

TIPOS_POLIGONO.forEach(({ s, nombre }) => {
  const terminos = [1, 2, 3, 4, 5, 6]
    .map(n => String(polyNum(s, n)).padStart(5))
    .join('');
  console.log(`  s=${s}  ${nombre} :${terminos}`);
});

// ---------------------------------------------------------------------------
//  SECCION 2: GENERACION DE CLAVES CON DIAGNOSTICO
// ---------------------------------------------------------------------------

console.log('');
console.log('--- Seccion 2: Generacion de claves (s=5, k=7) ---');
console.log('');

const { clavePublica, clavePrivada, periodo, bitsEquivalentes } =
  generarClaves(5, 7);
const diag = diagnosticar(5, 7);

console.log('  Parametros privados (secretos del servidor):');
console.log(`    s  = ${clavePrivada.s}   (tipo poligono: pentagonal)   [SECRETO]`);
console.log(`    k  = ${clavePrivada.k}   (desplazamiento inicial)       [SECRETO]`);
console.log('');
console.log('  Clave publica (compartida con el cliente):');
console.log(`    P1 = P(5, 1+7) = P(5, 8) = ${clavePublica}`);
console.log('');
console.log('  Propiedades criptograficas:');
console.log(`    MCD(P1=${clavePublica}, 256)  = ${mcd(clavePublica, 256)}`);
console.log(`    Periodo T          = 256 / ${mcd(clavePublica, 256)} = ${periodo} bytes`);
console.log(
  `    Espacio de claves  = ${diag.espacioTotal} combinaciones` +
  ` ~ ${bitsEquivalentes} bits equivalentes`
);
console.log('');
console.log('  Advertencias:');
diag.advertencias.forEach(aviso => console.log(`    ${aviso}`));

// ---------------------------------------------------------------------------
//  SECCION 3: CIFRADO BYTE A BYTE
// ---------------------------------------------------------------------------

const CREDENCIAL = 'Banc@2024';

console.log('');
console.log('--- Seccion 3: Cifrado de credencial bancaria ---');
console.log('');
console.log(`  Contrasena original : "${CREDENCIAL}"`);
console.log(`  Clave publica usada : P1 = ${clavePublica}`);
console.log(`  Formula mascara     : mask_i = (${clavePublica} * (i+1)) mod 256`);
console.log('  Formula cifrado     : C_i    = M_i XOR mask_i');
console.log('');

const { cifrado, mascaras } = cifrar(CREDENCIAL, clavePublica);
const bytesOrig             = Buffer.from(CREDENCIAL, 'utf8');
const bytesCif              = Buffer.from(cifrado, 'hex');

// Construir mapeo de posicion de byte a caracter legible,
// considerando que en UTF-8 un caracter puede ocupar varios bytes.
const etiquetasChar = [];
for (const caracter of CREDENCIAL) {
  const bytesCaracter = Buffer.byteLength(caracter, 'utf8');
  etiquetasChar.push(caracter);
  for (let j = 1; j < bytesCaracter; j++) {
    etiquetasChar.push('(cont)');  // bytes de continuacion UTF-8
  }
}

const SEP = '  ' + '-'.repeat(66);
console.log(SEP);
console.log('  Pos  | Char   | ASCII | Mascara | XOR (dec) | Hex');
console.log(SEP);
for (let i = 0; i < bytesOrig.length; i++) {
  const pos     = String(i + 1).padStart(4);
  const car     = (etiquetasChar[i] || '?').padEnd(6);
  const ascii   = String(bytesOrig[i]).padStart(5);
  const mascara = String(mascaras[i]).padStart(7);
  const xorDec  = String(bytesCif[i]).padStart(9);
  const hex     = bytesCif[i].toString(16).toUpperCase().padStart(4);
  console.log(`  ${pos} | ${car} | ${ascii} | ${mascara} | ${xorDec} | ${hex}`);
}
console.log(SEP);
console.log('');
console.log(`  Texto cifrado (hex) : ${cifrado}`);
console.log('  Este es el unico dato que viaja por la red.');
console.log('  Sin conocer (s, k), es computacionalmente inutil para un atacante.');

// ---------------------------------------------------------------------------
//  SECCION 4: DESCIFRADO EN EL SERVIDOR
// ---------------------------------------------------------------------------

console.log('');
console.log('--- Seccion 4: Descifrado en el servidor bancario ---');
console.log('');

const recuperado = descifrar(cifrado, clavePrivada);
const coincide   = recuperado === CREDENCIAL;

console.log(`  Texto cifrado recibido : ${cifrado}`);
console.log(`  Clave privada usada    : s=${clavePrivada.s}, k=${clavePrivada.k}`);
console.log(
  `  P1 reconstruida        : P(${clavePrivada.s}, ${1 + clavePrivada.k})` +
  ` = ${clavePublica}`
);
console.log(`  Contrasena recuperada  : "${recuperado}"`);
console.log(`  Coincide con original  : ${coincide ? '[OK] SI -- Descifrado exitoso' : '[ERROR] NO'}`);

// ---------------------------------------------------------------------------
//  SECCION 5: SIMULACION DE ATAQUE (MODELO DOLEV-YAO)
// ---------------------------------------------------------------------------

console.log('');
console.log('--- Seccion 5: Simulacion de ataque con clave incorrecta ---');
console.log('');
console.log(`  El adversario conoce el texto cifrado (${cifrado})`);
console.log(`  y la clave publica P1=${clavePublica}, pero NO conoce (s, k).`);
console.log('  Prueba diversas combinaciones:');
console.log('');

const INTENTOS_ATAQUE = [
  { s: 3, k: 2,  descripcion: 'triangular,  desplazamiento pequeno' },
  { s: 4, k: 10, descripcion: 'cuadrado,    desplazamiento medio'   },
  { s: 5, k: 7,  descripcion: 'pentagonal,  clave CORRECTA'         }
];

INTENTOS_ATAQUE.forEach(({ s, k, descripcion }) => {
  const resultado  = descifrar(cifrado, { s, k });
  const p1Intento  = polyNum(s, 1 + k);
  const esCorrecta = resultado === CREDENCIAL;
  const preview    = resultado.length > 30
    ? resultado.substring(0, 30) + '...'
    : resultado;

  console.log(`  Intento: s=${s}, k=${k}  (${descripcion})`);
  console.log(`    P1 reconstruida : ${p1Intento}`);
  console.log(`    Resultado       : "${preview}"`);
  console.log(`    Correcto        : ${esCorrecta ? '[OK] SI' : '[NO] Resultado ininteligible'}`);
  console.log('');
});

// ---------------------------------------------------------------------------
//  SECCION 6: ANALISIS DE PERIODICIDAD DE LA MASCARA
// ---------------------------------------------------------------------------

console.log('--- Seccion 6: Analisis de periodicidad de la mascara ---');
console.log('');
console.log(
  `  La mascara mask_i = (P1 * (i+1)) mod 256 es periodica.`
);
console.log(
  `  Para P1=${clavePublica}: T = 256 / MCD(${clavePublica}, 256)` +
  ` = 256 / ${mcd(clavePublica, 256)} = ${periodo} bytes.`
);
console.log('');

const PRIMEROS_N = 10;
const valoresMascara = Array.from(
  { length: PRIMEROS_N },
  (_, i) => (clavePublica * (i + 1)) % 256
);

console.log(`  Primeros ${PRIMEROS_N} valores de la mascara:`);
console.log(
  '  i     : ' + valoresMascara.map((_, i) => String(i + 1).padStart(5)).join('')
);
console.log(
  '  mask_i: ' + valoresMascara.map(m => String(m).padStart(5)).join('')
);
console.log('');
console.log(
  `  El patron se repite a partir de i = ${periodo + 1}.`
);
console.log(
  `  Para contrasenas bancarias tipicas (< 20 bytes) con T=${periodo}: ` +
  'SIN vulnerabilidad practica.'
);
console.log(
  `  Para mensajes de mas de ${periodo} bytes: la periodicidad permite ` +
  'recuperar la mascara por XOR entre segmentos equivalentes.'
);
console.log('');
console.log(
  '  Solucion propuesta (v2.0): derivar la mascara con ' +
  'mask_i = SHA-256(P1 || nonce || i) mod 256.'
);
console.log('');
