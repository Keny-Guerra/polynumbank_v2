'use strict';

/**
 * cifrado_credenciales.js
 *
 * Menu interactivo con tres opciones:
 *   1. CIFRAR    — ingresa texto plano, muestra proceso byte a byte y hex
 *   2. DESCIFRAR — ingresa hex cifrado, muestra proceso byte a byte y texto
 *   3. VERIFICAR — cifra y descifra automaticamente para confirmar
 *
 * Ejecutar: node demo/cifrado_credenciales.js
 */

const readline = require('readline');
const path     = require('path');
const { generarClaves, polyNum } = require(
  path.join(__dirname, '..', 'src', 'polynum')
);

// ---------------------------------------------------------------------------
//  CONFIGURACION (igual que servidor.js)
// ---------------------------------------------------------------------------

const S = 5;
const K = 7;
const { clavePublica: P1 } = generarClaves(S, K);

// ---------------------------------------------------------------------------
//  COLORES ANSI
// ---------------------------------------------------------------------------

const bold    = t => `\x1b[1m${t}\x1b[0m`;
const cyan    = t => `\x1b[36m${t}\x1b[0m`;
const green   = t => `\x1b[32m${t}\x1b[0m`;
const yellow  = t => `\x1b[33m${t}\x1b[0m`;
const red     = t => `\x1b[31m${t}\x1b[0m`;
const blue    = t => `\x1b[34m${t}\x1b[0m`;
const magenta = t => `\x1b[35m${t}\x1b[0m`;
const white   = t => `\x1b[97m${t}\x1b[0m`;
const gray    = t => `\x1b[90m${t}\x1b[0m`;

const pL = (v, w) => String(v).padStart(w);
const pR = (v, w) => String(v).padEnd(w);

const L1 = cyan('='.repeat(66));
const L2 = gray('-'.repeat(66));

// ---------------------------------------------------------------------------
//  CIFRADO PURO
// ---------------------------------------------------------------------------

function cifrarTexto(texto) {
  const bytes    = Buffer.from(texto, 'utf8');
  const cifrado  = Buffer.alloc(bytes.length);
  const mascaras = [];

  for (let i = 0; i < bytes.length; i++) {
    const mascara = (P1 * (i + 1)) % 256;
    mascaras.push(mascara);
    cifrado[i] = bytes[i] ^ mascara;
  }

  return {
    hex     : cifrado.toString('hex').toUpperCase(),
    mascaras,
    origBytes: Array.from(bytes),
    cifBytes : Array.from(cifrado)
  };
}

// ---------------------------------------------------------------------------
//  DESCIFRADO PURO
// ---------------------------------------------------------------------------

function descifrarHex(hex) {
  const bytes     = Buffer.from(hex, 'hex');
  const resultado = Buffer.alloc(bytes.length);
  const mascaras  = [];

  for (let i = 0; i < bytes.length; i++) {
    const mascara = (P1 * (i + 1)) % 256;
    mascaras.push(mascara);
    resultado[i] = bytes[i] ^ mascara;
  }

  return {
    texto   : resultado.toString('utf8'),
    mascaras,
    hexBytes: Array.from(bytes),
    recBytes: Array.from(resultado)
  };
}

// ---------------------------------------------------------------------------
//  BANNER
// ---------------------------------------------------------------------------

function banner() {
  process.stdout.write('\x1Bc');
  console.log('');
  console.log(L1);
  console.log(bold(white('   POLY-NUM  ─  CIFRADO Y DESCIFRADO INTERACTIVO')));
  console.log(gray('   Escuela de Ingenieria de Sistemas  ─  UCSM  ─  v1.1.0'));
  console.log(L1);
  console.log('');
  console.log(
    '  ' + gray('s  =') + ' ' + yellow('5') + '  ' +
    gray('k  =') + ' ' + yellow('7') + '  ' +
    gray('P1 =') + ' ' + bold(green(String(P1))) +
    gray('  [P(5, 8) = 92]')
  );
  console.log('');
  console.log('  ' + gray('Cifrar    : C_i = M_i  XOR  (P1 x (i+1)) mod 256'));
  console.log('  ' + gray('Descifrar : M_i = C_i  XOR  (P1 x (i+1)) mod 256'));
  console.log('');
  console.log(L2);
  console.log('');
  console.log(bold('  Selecciona una opcion:'));
  console.log('');
  console.log('  ' + cyan('[1]') + '  Cifrar        — texto plano  →  hex cifrado');
  console.log('  ' + green('[2]') + '  Descifrar     — hex cifrado  →  texto plano');
  console.log('  ' + yellow('[3]') + '  Cifrar + Descifrar  — proceso completo de verificacion');
  console.log('  ' + red('[0]') + '  Salir');
  console.log('');
}

// ---------------------------------------------------------------------------
//  TABLA CIFRADO
// ---------------------------------------------------------------------------

function tablaCifrado(usuario, password) {
  const r     = cifrarTexto(password);
  const chars = [];
  for (const cp of password) {
    const bl = Buffer.byteLength(cp, 'utf8');
    chars.push(cp);
    for (let j = 1; j < bl; j++) chars.push('·');
  }

  console.log('');
  console.log(L1);
  console.log(bold(white('  RESULTADO DEL CIFRADO')));
  console.log(L1);
  console.log('');
  console.log('  ' + gray('Usuario         :') + '  ' + bold(cyan(usuario)));
  console.log('  ' + gray('Texto plano     :') + '  ' + bold(yellow('"' + password + '"')));
  console.log('  ' + gray('Clave P1        :') + '  ' + bold(green(String(P1))));
  console.log('');
  console.log(bold('  Proceso byte a byte:'));
  console.log('');
  console.log('  ' + L2);
  console.log(
    '  ' +
    bold(gray(pR('Pos', 4))) + '  ' +
    bold(gray(pR('Char', 6))) + '  ' +
    bold(gray(pL('ASCII', 5))) + '  ' +
    bold(gray(pL('Mascara', 9))) + '  ' +
    bold(gray(pR('Operacion XOR', 22))) + '  ' +
    bold(gray(pL('Dec', 4))) + '  ' +
    bold(gray(pL('Hex', 4)))
  );
  console.log('  ' + L2);

  for (let i = 0; i < r.origBytes.length; i++) {
    const car     = chars[i] || '?';
    const ascii   = r.origBytes[i];
    const prod    = P1 * (i + 1);
    const mascara = prod % 256;
    const dec     = r.cifBytes[i];
    const hex     = dec.toString(16).toUpperCase().padStart(2, '0');
    const formula = '(' + P1 + 'x' + (i+1) + ')%256=' + mascara;
    const op      = ascii + ' XOR ' + mascara + ' = ' + dec;

    console.log(
      '  ' +
      gray(pR(i + 1, 4))             + '  ' +
      yellow(pR('"' + car + '"', 6)) + '  ' +
      white(pL(ascii, 5))            + '  ' +
      magenta(pL(formula, 9))        + '  ' +
      blue(pR(op, 22))               + '  ' +
      cyan(pL(dec, 4))               + '  ' +
      bold(green(pL(hex, 4)))
    );
  }

  console.log('  ' + L2);
  console.log('');
  console.log('  ' + gray('Texto plano    :') + '  ' + yellow('"' + password + '"'));
  console.log('  ' + gray('Texto cifrado  :') + '  ' + bold(green(r.hex)));
  console.log('');
  console.log('  ' + gray('Lo que viaja por la red:'));
  console.log('  ' + gray('  { usuario: "' + usuario + '", passwordCifrado: "' + r.hex + '" }'));
  console.log('  ' + red('  La contrasena NUNCA viaja en texto plano.'));
  console.log('');
  console.log(L1);

  return r.hex;
}

// ---------------------------------------------------------------------------
//  TABLA DESCIFRADO
// ---------------------------------------------------------------------------

function tablaDescifrado(hexInput) {

  if (hexInput.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hexInput)) {
    console.log('');
    console.log(red('  Error: no es un hex valido. Ejemplo: 1ED97A138C1AB4D208'));
    console.log('');
    return null;
  }

  const r     = descifrarHex(hexInput);
  const chars = [];
  for (const cp of r.texto) {
    const bl = Buffer.byteLength(cp, 'utf8');
    chars.push(cp);
    for (let j = 1; j < bl; j++) chars.push('·');
  }

  console.log('');
  console.log(L1);
  console.log(bold(white('  RESULTADO DEL DESCIFRADO')));
  console.log(L1);
  console.log('');
  console.log('  ' + gray('Hex recibido    :') + '  ' + bold(cyan(hexInput)));
  console.log('  ' + gray('Clave P1        :') + '  ' + bold(green(String(P1))));
  console.log('  ' + gray('Clave privada   :') + '  ' + red('s=' + S + ', k=' + K));
  console.log('  ' + gray('P1 reconstruida :') + '  ' + green('P(' + S + ', 1+' + K + ') = P(' + S + ', ' + (1+K) + ') = ' + P1));
  console.log('');
  console.log(bold('  Proceso byte a byte:'));
  console.log('');
  console.log('  ' + L2);
  console.log(
    '  ' +
    bold(gray(pR('Pos', 4))) + '  ' +
    bold(gray(pR('Hex', 6))) + '  ' +
    bold(gray(pL('Dec', 5))) + '  ' +
    bold(gray(pL('Mascara', 9))) + '  ' +
    bold(gray(pR('Operacion XOR', 22))) + '  ' +
    bold(gray(pL('Res', 4))) + '  ' +
    bold(gray(pL('Char', 6)))
  );
  console.log('  ' + L2);

  for (let i = 0; i < r.hexBytes.length; i++) {
    const hexByte = r.hexBytes[i].toString(16).toUpperCase().padStart(2, '0');
    const dec     = r.hexBytes[i];
    const mascara = r.mascaras[i];
    const recup   = r.recBytes[i];
    const car     = chars[i] !== undefined ? '"' + chars[i] + '"' : '?';
    const formula = '(' + P1 + 'x' + (i+1) + ')%256=' + mascara;
    const op      = dec + ' XOR ' + mascara + ' = ' + recup;

    console.log(
      '  ' +
      gray(pR(i + 1, 4))           + '  ' +
      cyan(pR('0x' + hexByte, 6))  + '  ' +
      white(pL(dec, 5))            + '  ' +
      magenta(pL(formula, 9))      + '  ' +
      blue(pR(op, 22))             + '  ' +
      white(pL(recup, 4))          + '  ' +
      yellow(pR(car, 6))
    );
  }

  console.log('  ' + L2);
  console.log('');
  console.log('  ' + gray('Hex recibido    :') + '  ' + cyan(hexInput));
  console.log('  ' + gray('Texto descifrado:') + '  ' + bold(yellow('"' + r.texto + '"')));
  console.log('');
  console.log(L1);

  return r.texto;
}

// ---------------------------------------------------------------------------
//  HELPER READLINE
// ---------------------------------------------------------------------------

function preguntar(rl, texto) {
  return new Promise(resolve => rl.question(texto, r => resolve(r.trim())));
}

// ---------------------------------------------------------------------------
//  MENU PRINCIPAL
// ---------------------------------------------------------------------------

async function menu() {
  banner();

  const rl = readline.createInterface({
    input : process.stdin,
    output: process.stdout
  });

  const opcion = await preguntar(rl, cyan('  Opcion: '));
  console.log('');

  // ── OPCION 1: CIFRAR ─────────────────────────────────────────────────────
  if (opcion === '1') {
    const usuario  = await preguntar(rl, cyan('  Usuario    : '));
    const password = await preguntar(rl, cyan('  Contrasena : '));
    rl.close();

    if (!usuario || !password) {
      console.log(red('  Error: usuario y contrasena no pueden estar vacios.'));
      return setTimeout(menu, 800);
    }

    tablaCifrado(usuario, password);
  }

  // ── OPCION 2: DESCIFRAR ───────────────────────────────────────────────────
  else if (opcion === '2') {
    console.log(gray('  Ingresa el hex cifrado. Ejemplo: 1ED97A138C1AB4D208'));
    console.log('');
    const hexInput = await preguntar(rl, cyan('  Hex cifrado: '));
    rl.close();

    if (!hexInput) {
      console.log(red('  Error: el hex no puede estar vacio.'));
      return setTimeout(menu, 800);
    }

    tablaDescifrado(hexInput.toUpperCase());
  }

  // ── OPCION 3: CIFRAR + DESCIFRAR (verificacion completa) ─────────────────
  else if (opcion === '3') {
    const usuario  = await preguntar(rl, cyan('  Usuario    : '));
    const password = await preguntar(rl, cyan('  Contrasena : '));
    rl.close();

    if (!usuario || !password) {
      console.log(red('  Error: usuario y contrasena no pueden estar vacios.'));
      return setTimeout(menu, 800);
    }

    // Paso 1: Cifrar
    const hexGenerado = tablaCifrado(usuario, password);

    await new Promise(r => setTimeout(r, 400));

    // Paso 2: Descifrar el mismo hex
    console.log('');
    console.log(bold(white('  Ahora descifra el hex generado para verificar:')));
    const textoRecuperado = tablaDescifrado(hexGenerado);

    // Verificacion final
    const coincide = textoRecuperado === password;
    console.log('');
    console.log(L1);
    console.log(bold(white('  VERIFICACION FINAL')));
    console.log(L1);
    console.log('');
    console.log('  ' + gray('Texto original  :') + '  ' + yellow('"' + password + '"'));
    console.log('  ' + gray('Texto cifrado   :') + '  ' + green(hexGenerado));
    console.log('  ' + gray('Texto descifrado:') + '  ' + yellow('"' + textoRecuperado + '"'));
    console.log('');
    console.log('  ' + gray('Coinciden       :') + '  ' +
      (coincide
        ? bold(green('SI  ─  El cifrado POLY-NUM es correcto y reversible'))
        : bold(red('NO  ─  Error en el proceso')))
    );
    console.log('');
    console.log(L1);
  }

  // ── OPCION 0: SALIR ───────────────────────────────────────────────────────
  else if (opcion === '0') {
    rl.close();
    console.log(L2);
    console.log(gray('  Sesion POLY-NUM finalizada.'));
    console.log(L2 + '\n');
    return process.exit(0);
  }

  else {
    rl.close();
    console.log(red('  Opcion invalida.'));
    return setTimeout(menu, 600);
  }

  // ── Preguntar si volver al menu ───────────────────────────────────────────
  const rl2 = readline.createInterface({
    input : process.stdin,
    output: process.stdout
  });

  const continuar = await preguntar(rl2, cyan('  Volver al menu? (s/n): '));
  rl2.close();

  if (continuar.toLowerCase() === 's') {
    menu();
  } else {
    console.log('');
    console.log(L2);
    console.log(gray('  Sesion POLY-NUM finalizada.'));
    console.log(L2 + '\n');
    process.exit(0);
  }
}

// ---------------------------------------------------------------------------
//  INICIO
// ---------------------------------------------------------------------------

menu();
