'use strict';

/**
 * cifrado_credenciales.js
 *
 * Script interactivo: ingresa usuario y contrasena,
 * muestra el proceso completo de cifrado POLY-NUM detalle a detalle.
 *
 * Ejecutar desde la raiz del proyecto:
 *   node demo/cifrado_credenciales.js
 */

const readline = require('readline');
const path     = require('path');
const { generarClaves, cifrar, polyNum } = require(
  path.join(__dirname, '..', 'src', 'polynum')
);

// ---------------------------------------------------------------------------
//  CONFIGURACION CRIPTOGRAFICA (igual que servidor.js)
// ---------------------------------------------------------------------------

const S = 5;
const K = 7;
const { clavePublica: P1 } = generarClaves(S, K);

// ---------------------------------------------------------------------------
//  COLORES ANSI
// ---------------------------------------------------------------------------

const bold    = t => `\x1b[1m${t}\x1b[0m`;
const dim     = t => `\x1b[2m${t}\x1b[0m`;
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

const SEP1 = cyan('='.repeat(68));
const SEP2 = gray('-'.repeat(68));

// ---------------------------------------------------------------------------
//  BANNER
// ---------------------------------------------------------------------------

function banner() {
  process.stdout.write('\x1Bc');
  console.log('');
  console.log(SEP1);
  console.log(bold(white('   POLY-NUM  ─  VISUALIZADOR DE CIFRADO DE CREDENCIALES')));
  console.log(gray('   Escuela de Ingenieria de Sistemas  ─  UCSM  ─  v1.1.0'));
  console.log(SEP1);
  console.log('');
  console.log(bold('  Parametros criptograficos activos:'));
  console.log('');
  console.log('  ' + pR(gray('s  ='), 10) + yellow('5') +
              gray('  (tipo poligono: pentagonal)     ') + red('[SECRETO]'));
  console.log('  ' + pR(gray('k  ='), 10) + yellow('7') +
              gray('  (desplazamiento inicial)         ') + red('[SECRETO]'));
  console.log('  ' + pR(gray('P1 ='), 10) + bold(green(String(P1))) +
              gray('  ← P(5, 1+7) = P(5, 8)           ') + green('[PUBLICO]'));
  console.log('');
  console.log('  ' + gray('Formula clave publica : P(s,n) = n·[(s-2)·n-(s-4)] / 2'));
  console.log('  ' + gray('Formula cifrado       : C_i = M_i XOR (P1·(i+1) mod 256)'));
  console.log('  ' + gray('Formula descifrado    : M_i = C_i XOR (P1·(i+1) mod 256)'));
  console.log('');
  console.log(SEP2);
  console.log('');
}

// ---------------------------------------------------------------------------
//  MOSTRAR PROCESO DE CIFRADO
// ---------------------------------------------------------------------------

function mostrarCifrado(usuario, password) {

  const resultado = cifrar(password, P1);
  const bytesOrig = Buffer.from(password, 'utf8');
  const bytesCif  = Buffer.from(resultado.cifrado, 'hex');

  // Mapeo correcto byte → caracter para UTF-8 multibyte
  const chars = [];
  for (const cp of password) {
    const bl = Buffer.byteLength(cp, 'utf8');
    chars.push(cp);
    for (let j = 1; j < bl; j++) chars.push('·');
  }

  // ── Encabezado ──────────────────────────────────────────────
  console.log('');
  console.log(SEP1);
  console.log(bold(white('  PROCESO DE CIFRADO POLY-NUM')));
  console.log(SEP1);

  // ── Datos de entrada ─────────────────────────────────────────
  console.log('');
  console.log(bold('  [ Datos ingresados ]'));
  console.log('');
  console.log('  ' + gray('Usuario         :') + '  ' + bold(cyan(usuario)));
  console.log('  ' + gray('Contrasena      :') + '  ' + bold(yellow('"' + password + '"')));
  console.log('  ' + gray('Clave publica   :') + '  ' + bold(green('P1 = ' + P1)));
  console.log('  ' + gray('Bytes a cifrar  :') + '  ' + white(bytesOrig.length + ' bytes'));

  // ── Calculo de P1 ────────────────────────────────────────────
  console.log('');
  console.log(bold('  [ Generacion de la clave publica ]'));
  console.log('');
  console.log('  ' + gray('P(s, n)  =  n · [(s-2)·n - (s-4)] / 2'));
  console.log('  ' + gray('P(5, 8)  =  8 · [(5-2)·8 - (5-4)] / 2'));
  console.log('  ' + gray('         =  8 · [24 - 1] / 2'));
  console.log('  ' + gray('         =  8 · 23 / 2'));
  console.log('  ' + gray('         =  184 / 2  =  ') + bold(green(String(P1))));

  // ── Tabla byte a byte ────────────────────────────────────────
  console.log('');
  console.log(bold('  [ Cifrado byte a byte ]'));
  console.log('');
  console.log('  ' + SEP2);
  console.log(
    '  ' +
    bold(gray(pR('Pos',  4)))  + '  ' +
    bold(gray(pR('Car',  5)))  + '  ' +
    bold(gray(pL('ASCII', 5))) + '  ' +
    bold(gray(pL('Mascara (i+1)·P1 mod 256', 28))) + '  ' +
    bold(gray(pL('XOR', 5)))   + '  ' +
    bold(gray(pL('Hex', 4)))
  );
  console.log('  ' + SEP2);

  for (let i = 0; i < bytesOrig.length; i++) {
    const car     = chars[i] || '?';
    const ascii   = bytesOrig[i];
    const factor  = i + 1;
    const producto= P1 * factor;
    const mascara = producto % 256;
    const xorVal  = bytesCif[i];
    const hexByte = xorVal.toString(16).toUpperCase().padStart(2, '0');

    // Formula expandida de la mascara
    const formulaMascara = '(' + P1 + '×' + factor + ')mod256 = ' +
                           producto + (producto >= 256 ? ' mod 256' : '') +
                           ' = ' + mascara;

    console.log(
      '  ' +
      gray(pR(i + 1,  4))                   + '  ' +
      yellow(pR('"' + car + '"', 5))         + '  ' +
      white(pL(ascii, 5))                    + '  ' +
      magenta(pL(formulaMascara, 28))        + '  ' +
      cyan(pL(ascii + ' ⊕ ' + mascara + ' = ' + xorVal, 18)) + '  ' +
      bold(green(pL(hexByte, 4)))
    );
  }

  console.log('  ' + SEP2);

  // ── Mascaras usadas ──────────────────────────────────────────
  console.log('');
  console.log(bold('  [ Secuencia de mascaras posicionales ]'));
  console.log('');
  console.log(gray('  mask_i = (P1 × i) mod 256 donde i = posicion 1..n'));
  console.log('');
  resultado.mascaras.forEach((m, i) => {
    const producto = P1 * (i + 1);
    process.stdout.write(
      '  ' +
      gray('i=' + (i+1) + ':') + ' ' +
      '(' + green(String(P1)) + '×' + white(i+1) + ')=' +
      white(String(producto)) +
      (producto >= 256 ? gray(' mod 256=') : gray('=')) +
      magenta(String(m)) +
      '    '
    );
    if ((i + 1) % 3 === 0) process.stdout.write('\n');
  });
  if (resultado.mascaras.length % 3 !== 0) process.stdout.write('\n');

  // ── Resultado final ──────────────────────────────────────────
  console.log('');
  console.log(bold('  [ Resultado del cifrado ]'));
  console.log('');
  console.log('  ' + gray('Texto plano     :') + '  ' + yellow('"' + password + '"'));
  console.log('  ' + gray('Texto cifrado   :') + '  ' + bold(green(resultado.cifrado)));
  console.log('  ' + gray('Periodo T       :') + '  ' + white(resultado.periodo + ' bytes') +
              gray('  (256 / MCD(' + P1 + ', 256) = 256/4)'));

  // ── Transmision por red ──────────────────────────────────────
  console.log('');
  console.log(bold('  [ Lo que viaja por la red ]'));
  console.log('');
  console.log('  ' + gray('{'));
  console.log('  ' + gray('  usuario         : ') + cyan('"' + usuario + '"'));
  console.log('  ' + gray('  passwordCifrado : ') + bold(green('"' + resultado.cifrado + '"')));
  console.log('  ' + gray('}'));
  console.log('');
  console.log('  ' + red('La contrasena "' + password + '" NUNCA sale del dispositivo.'));

  // ── Verificacion ─────────────────────────────────────────────
  console.log('');
  console.log(bold('  [ Verificacion: descifrado con la misma P1 ]'));
  console.log('');

  const bc = Buffer.from(resultado.cifrado, 'hex');
  const br = Buffer.alloc(bc.length);
  for (let i = 0; i < bc.length; i++) {
    br[i] = bc[i] ^ ((P1 * (i + 1)) % 256);
  }
  const descifrado = br.toString('utf8');
  const ok         = descifrado === password;

  for (let i = 0; i < bc.length; i++) {
    const hexB  = bc[i].toString(16).toUpperCase().padStart(2, '0');
    const masc  = (P1 * (i + 1)) % 256;
    const recup = br[i];
    const car   = chars[i] || '?';
    console.log(
      '  ' +
      gray('Byte ' + pL(i+1, 2) + ':') + '  ' +
      green('0x' + hexB) + gray(' XOR ') +
      magenta(pL(masc, 3)) + gray(' = ') +
      cyan(pL(recup, 3)) +
      gray('  →  ') +
      yellow('"' + car + '"')
    );
  }

  console.log('');
  console.log('  ' + gray('Texto recuperado :') + '  ' + yellow('"' + descifrado + '"'));
  console.log('  ' + gray('Resultado        :') + '  ' +
    (ok ? bold(green('CORRECTO ─ Cifrado y descifrado exactos'))
        : bold(red('ERROR ─ No coincide'))));
  console.log('');
  console.log(SEP1);
}

// ---------------------------------------------------------------------------
//  BUCLE INTERACTIVO
// ---------------------------------------------------------------------------

function preguntar() {
  banner();
  console.log(bold('  Ingresa las credenciales para visualizar el cifrado:'));
  console.log('');

  const rl = readline.createInterface({
    input : process.stdin,
    output: process.stdout
  });

  rl.question(cyan('  Usuario    : '), (usuario) => {
    usuario = usuario.trim();

    if (!usuario) {
      console.log(red('\n  Error: el usuario no puede estar vacio.\n'));
      rl.close();
      setTimeout(preguntar, 800);
      return;
    }

    rl.question(cyan('  Contrasena : '), (password) => {
      password = password.trim();

      if (!password) {
        console.log(red('\n  Error: la contrasena no puede estar vacia.\n'));
        rl.close();
        setTimeout(preguntar, 800);
        return;
      }

      rl.close();
      mostrarCifrado(usuario, password);

      // Preguntar si continuar
      const rl2 = readline.createInterface({
        input : process.stdin,
        output: process.stdout
      });

      console.log('');
      rl2.question(cyan('  Cifrar otra credencial? (s/n): '), (resp) => {
        rl2.close();
        if (resp.trim().toLowerCase() === 's') {
          preguntar();
        } else {
          console.log('');
          console.log(SEP2);
          console.log(gray('  Sesion POLY-NUM finalizada.'));
          console.log(SEP2 + '\n');
          process.exit(0);
        }
      });
    });
  });
}

// ── Inicio ───────────────────────────────────────────────────
preguntar();
