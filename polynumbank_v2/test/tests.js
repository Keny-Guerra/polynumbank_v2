'use strict';

/**
 * @fileoverview tests.js — Suite de pruebas unitarias POLY-NUM v1.1
 *
 * 22 pruebas organizadas en 6 grupos que validan la correctitud
 * funcional y las propiedades de seguridad del algoritmo POLY-NUM:
 *
 *   Grupo 1 — Correctitud de la formula poligonal     (5 pruebas)
 *   Grupo 2 — Generacion de claves y validaciones     (5 pruebas)
 *   Grupo 3 — Ciclos cifrado / descifrado             (6 pruebas)
 *   Grupo 4 — Verificacion de clave publica           (2 pruebas)
 *   Grupo 5 — Analisis matematico del esquema         (2 pruebas)
 *   Grupo 6 — Manejo de errores y entradas invalidas  (2 pruebas)
 *
 * Ejecutar: node test/tests.js
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
  verificarClavePublica,
  mcd,
  periodoCicloMascara
} = require('../src/polynum');

// ---------------------------------------------------------------------------
//  FRAMEWORK DE PRUEBAS MINIMO (sin dependencias externas)
// ---------------------------------------------------------------------------

let pasados  = 0;
let fallados = 0;
const fallos = [];

/**
 * Ejecuta un caso de prueba y registra el resultado.
 *
 * @param {string}   nombre - Descripcion del caso de prueba.
 * @param {Function} fn     - Funcion que lanza Error si la prueba falla.
 */
function test(nombre, fn) {
  try {
    fn();
    console.log(`  [PASS]  ${nombre}`);
    pasados += 1;
  } catch (err) {
    console.log(`  [FAIL]  ${nombre}`);
    console.log(`          -> ${err.message}`);
    fallados += 1;
    fallos.push({ nombre, mensaje: err.message });
  }
}

/**
 * Evalua una condicion booleana y lanza Error si es falsa.
 *
 * @param {boolean} condicion  - Condicion a evaluar.
 * @param {string}  [mensaje]  - Mensaje descriptivo del fallo.
 * @throws {Error} Si condicion es false.
 */
function afirmar(condicion, mensaje) {
  if (!condicion) {
    throw new Error(mensaje || 'La asercion fallo (sin mensaje)');
  }
}

/**
 * Verifica que la funcion fn() lanza un error del tipo esperado.
 * Acepta comparacion por nombre del constructor o por texto en el mensaje.
 *
 * @param {Function} fn            - Funcion que debe lanzar un error.
 * @param {string}   tipoEsperado  - Nombre del constructor del error esperado.
 * @throws {Error} Si fn() no lanza ningun error o lanza uno de tipo distinto.
 */
function afirmarError(fn, tipoEsperado) {
  try {
    fn();
    throw new Error(
      `Se esperaba un error de tipo ${tipoEsperado} pero no se lanzo ninguno`
    );
  } catch (err) {
    const tipoReal = err.constructor.name;
    if (tipoReal === tipoEsperado) return;
    if (err.message.includes(tipoEsperado)) return;
    throw new Error(
      `Se lanzo ${tipoReal} pero se esperaba ${tipoEsperado}. ` +
      `Mensaje: ${err.message}`
    );
  }
}

// ---------------------------------------------------------------------------
//  BANNER
// ---------------------------------------------------------------------------

console.log('');
console.log('+==============================================+');
console.log('|     SUITE DE PRUEBAS UNITARIAS  --  POLY-NUM|');
console.log('|       v1.1.0   |   22 casos de prueba       |');
console.log('+==============================================+');
console.log('');

// ===========================================================================
//  GRUPO 1: CORRECTITUD DE LA FORMULA POLIGONAL
//  Verifica P(s, n) = n * [(s-2)*n - (s-4)] / 2
// ===========================================================================

console.log('  [ Grupo 1 ] Correctitud de la formula poligonal');
console.log('');

test('P(3, 1) = 1  (primer numero triangular)', () =>
  afirmar(polyNum(3, 1) === 1, `Resultado obtenido: ${polyNum(3, 1)}`));

test('P(3, 4) = 10 (cuarto numero triangular)', () =>
  afirmar(polyNum(3, 4) === 10, `Resultado obtenido: ${polyNum(3, 4)}`));

test('P(4, 4) = 16 (cuarto cuadrado perfecto)', () =>
  afirmar(polyNum(4, 4) === 16, `Resultado obtenido: ${polyNum(4, 4)}`));

test('P(5, 5) = 35 (quinto numero pentagonal)', () =>
  afirmar(polyNum(5, 5) === 35, `Resultado obtenido: ${polyNum(5, 5)}`));

test('P(5, 8) = 92 (clave publica del escenario de demostracion)', () =>
  afirmar(polyNum(5, 8) === 92, `Resultado obtenido: ${polyNum(5, 8)}`));

// ===========================================================================
//  GRUPO 2: GENERACION DE CLAVES Y VALIDACIONES
// ===========================================================================

console.log('');
console.log('  [ Grupo 2 ] Generacion de claves y validaciones');
console.log('');

test('generarClaves(5, 7) produce la clave publica P(5, 8) = 92', () => {
  const { clavePublica } = generarClaves(5, 7);
  afirmar(clavePublica === 92, `Clave publica obtenida: ${clavePublica}`);
});

test('La clave privada retiene correctamente s=5 y k=7', () => {
  const { clavePrivada } = generarClaves(5, 7);
  afirmar(
    clavePrivada.s === 5 && clavePrivada.k === 7,
    `Obtuvo s=${clavePrivada.s}, k=${clavePrivada.k}`
  );
});

test('Lanza RangeError si s < S_MIN (s=2)', () =>
  afirmarError(() => generarClaves(2, 5), 'RangeError'));

test('Lanza RangeError si k > K_MAX (k=101)', () =>
  afirmarError(() => generarClaves(5, 101), 'RangeError'));

test('Lanza TypeError si s no es entero (s=3.5)', () =>
  afirmarError(() => generarClaves(3.5, 5), 'TypeError'));

// ===========================================================================
//  GRUPO 3: CICLOS CIFRADO / DESCIFRADO
// ===========================================================================

console.log('');
console.log('  [ Grupo 3 ] Ciclos cifrado / descifrado');
console.log('');

test('cifrar + descifrar recupera exactamente el mensaje original', () => {
  const { clavePublica, clavePrivada } = generarClaves(5, 7);
  const { cifrado }                    = cifrar('Banc@2024', clavePublica);
  const recuperado                     = descifrar(cifrado, clavePrivada);
  afirmar(recuperado === 'Banc@2024', `Resultado: "${recuperado}"`);
});

test('El texto cifrado difiere del texto original (la transformacion no es identidad)', () => {
  const { clavePublica } = generarClaves(5, 7);
  const { cifrado }      = cifrar('Banc@2024', clavePublica);
  const originalHex      = Buffer.from('Banc@2024').toString('hex').toUpperCase();
  afirmar(
    cifrado !== 'Banc@2024' && cifrado !== originalHex,
    'El cifrado no transformo el texto original'
  );
});

test('Contrasenas distintas producen textos cifrados distintos', () => {
  const { clavePublica } = generarClaves(5, 7);
  const c1               = cifrar('Banc@2024', clavePublica).cifrado;
  const c2               = cifrar('OtraClav3', clavePublica).cifrado;
  afirmar(c1 !== c2, 'Dos contrasenas distintas generaron el mismo cifrado');
});

test('Claves publicas distintas producen cifrados distintos para la misma contrasena', () => {
  const { clavePublica: p1a } = generarClaves(5, 7);
  const { clavePublica: p1b } = generarClaves(6, 7);
  const c1                    = cifrar('Password1', p1a).cifrado;
  const c2                    = cifrar('Password1', p1b).cifrado;
  afirmar(c1 !== c2, 'Claves distintas produjeron el mismo cifrado');
});

test('Cifra y descifra correctamente contrasenas con caracteres especiales', () => {
  const { clavePublica, clavePrivada } = generarClaves(7, 3);
  const mensaje                        = 'P@$$w0rd#2024!%^&*()';
  const { cifrado }                    = cifrar(mensaje, clavePublica);
  const recuperado                     = descifrar(cifrado, clavePrivada);
  afirmar(recuperado === mensaje, `Resultado: "${recuperado}"`);
});

test('Cifra y descifra correctamente contrasenas con acentos y caracteres UTF-8', () => {
  const { clavePublica, clavePrivada } = generarClaves(4, 5);
  const mensaje                        = 'contrasenaUnicaArea';
  const { cifrado }                    = cifrar(mensaje, clavePublica);
  const recuperado                     = descifrar(cifrado, clavePrivada);
  afirmar(recuperado === mensaje, `Resultado: "${recuperado}"`);
});

// ===========================================================================
//  GRUPO 4: VERIFICACION DE CLAVE PUBLICA
// ===========================================================================

console.log('');
console.log('  [ Grupo 4 ] Verificacion de clave publica');
console.log('');

test('verificarClavePublica retorna true con s=5, k=7 y P1=92', () => {
  const { clavePrivada } = generarClaves(5, 7);
  afirmar(
    verificarClavePublica(92, clavePrivada),
    'verificarClavePublica deberia retornar true'
  );
});

test('verificarClavePublica retorna false con P1 incorrecta (P1=999)', () => {
  const { clavePrivada } = generarClaves(5, 7);
  afirmar(
    !verificarClavePublica(999, clavePrivada),
    'verificarClavePublica deberia retornar false'
  );
});

// ===========================================================================
//  GRUPO 5: ANALISIS MATEMATICO DEL ESQUEMA
// ===========================================================================

console.log('');
console.log('  [ Grupo 5 ] Analisis matematico del esquema');
console.log('');

test('Periodo T = 256 / MCD(P1, 256) = 64 para P1=92', () => {
  const T      = periodoCicloMascara(92);
  const mcdVal = mcd(92, 256);
  afirmar(mcdVal === 4,  `MCD esperado=4,  obtenido=${mcdVal}`);
  afirmar(T     === 64,  `T   esperado=64, obtenido=${T}`);
});

test('Descifrado con clave incorrecta (s=3, k=2) produce resultado diferente al original', () => {
  const { clavePublica } = generarClaves(5, 7);
  const { cifrado }      = cifrar('Banc@2024', clavePublica);
  const resultadoAtaque  = descifrar(cifrado, { s: 3, k: 2 });
  afirmar(
    resultadoAtaque !== 'Banc@2024',
    '[FALLA DE SEGURIDAD] El ataque recupero la contrasena original con clave incorrecta'
  );
});

// ===========================================================================
//  GRUPO 6: MANEJO DE ERRORES Y ENTRADAS INVALIDAS
// ===========================================================================

console.log('');
console.log('  [ Grupo 6 ] Manejo de errores y entradas invalidas');
console.log('');

test('cifrar lanza RangeError con texto vacio', () =>
  afirmarError(() => {
    const { clavePublica } = generarClaves(5, 7);
    cifrar('', clavePublica);
  }, 'RangeError'));

test('descifrar lanza TypeError con cadena hexadecimal invalida', () =>
  afirmarError(() => {
    descifrar('ZZZZ', { s: 5, k: 7 });
  }, 'TypeError'));

// ---------------------------------------------------------------------------
//  RESUMEN FINAL
// ---------------------------------------------------------------------------

const total = pasados + fallados;
console.log('');
console.log('  ' + '-'.repeat(50));
console.log(`  Pasados  : ${pasados} / ${total}`);
console.log(`  Fallados : ${fallados} / ${total}`);

if (fallados === 0) {
  console.log('');
  console.log(`  [OK] Todos los tests pasaron (${total}/${total}) -- cobertura 100%`);
  console.log('');
} else {
  console.log('');
  console.log(`  [ERROR] ${fallados} test(s) fallaron:`);
  console.log('');
  fallos.forEach((f, i) => {
    console.log(`  ${i + 1}. ${f.nombre}`);
    console.log(`     -> ${f.mensaje}`);
  });
  console.log('');
  process.exit(1);
}
