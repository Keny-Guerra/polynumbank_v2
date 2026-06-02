'use strict';

process.stdout.write('\x1Bc'); // Limpia la consola al iniciar el servidor

/**
 * @fileoverview servidor.js -- Backend bancario POLY-NUM
 *
 * Servidor HTTP que implementa el protocolo POLY-NUM de cinco etapas.
 * Cada intento de autenticacion imprime en consola el proceso completo
 * byte a byte para fines de demostracion academica.
 *
 * Variables de entorno:
 *   POLY_S  Tipo de poligono s  (default: 5)
 *   POLY_K  Desplazamiento k    (default: 7)
 *   PORT    Puerto HTTP         (default: 3000)
 *
 * @version 1.1.0
 * @authors Baldarrago Samatelo, Piero
 *          De los Rios Peralta, Jean Mael
 *          Guerra Huanaco, Keny Russell
 *          Sayritupac, Asqui Jeampier
 * @institution Escuela Profesional de Ingenieria de Sistemas -- UCSM
 */

const http = require('http');
const {
  polyNum,
  generarClaves,
  verificarClavePublica,
  diagnosticar,
  constantes
} = require('./polynum');

// ---------------------------------------------------------------------------
//  CONFIGURACION
// ---------------------------------------------------------------------------

const CONFIG = {
  s     : parseInt(process.env.POLY_S, 10) || 5,
  k     : parseInt(process.env.POLY_K, 10) || 7,
  puerto: parseInt(process.env.PORT,   10) || 3000
};

let clavePublica;
let clavePrivada;
let infoDiagnostico;

try {
  ({ clavePublica, clavePrivada } = generarClaves(CONFIG.s, CONFIG.k));
  infoDiagnostico = diagnosticar(CONFIG.s, CONFIG.k);
} catch (err) {
  process.stderr.write(`\n[ERROR FATAL] Parametros de clave invalidos: ${err.message}\n`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
//  BASE DE DATOS SIMULADA
// ---------------------------------------------------------------------------

const USUARIOS_BD = new Map([
  ['jperez',  'Banc@2024'],
  ['mgarcia', 'Seguro#99'],
  ['admin',   'Admin!2025']
]);

// ---------------------------------------------------------------------------
//  CONTROL DE INTENTOS FALLIDOS
// ---------------------------------------------------------------------------

const registroIntentos      = new Map();
const MAX_INTENTOS_FALLIDOS = 5;
const VENTANA_BLOQUEO_MS    = 60_000;

function registrarFallo(usuario) {
  const ahora   = Date.now();
  const entrada = registroIntentos.get(usuario) || { intentos: 0, desde: ahora };
  if (ahora - entrada.desde > VENTANA_BLOQUEO_MS) {
    entrada.intentos = 0;
    entrada.desde    = ahora;
  }
  entrada.intentos += 1;
  registroIntentos.set(usuario, entrada);
  return entrada.intentos > MAX_INTENTOS_FALLIDOS;
}

function estaBloqueado(usuario) {
  const entrada = registroIntentos.get(usuario);
  if (!entrada) return false;
  if (Date.now() - entrada.desde > VENTANA_BLOQUEO_MS) return false;
  return entrada.intentos > MAX_INTENTOS_FALLIDOS;
}

// ---------------------------------------------------------------------------
//  DESCIFRADO CON LOG DETALLADO EN CONSOLA
//  Esta funcion descifra el hex y ademas imprime cada paso en pantalla.
// ---------------------------------------------------------------------------

/**
 * Descifra el hex recibido y muestra en consola el proceso completo
 * byte a byte: mascara posicional, operacion XOR y caracter recuperado.
 *
 * @param {string}               hexCifrado   - Texto cifrado en hex.
 * @param {{s:number, k:number}} clavePriv    - Clave privada del servidor.
 * @param {string}               usuario      - Para contextualizar el log.
 * @returns {string} Texto descifrado.
 */
function descifrarConLog(hexCifrado, clavePriv, usuario) {
  const { s, k }       = clavePriv;
  const p1Reconstruida = polyNum(s, 1 + k);
  const bytes          = Buffer.from(hexCifrado, 'hex');
  const resultado      = Buffer.alloc(bytes.length);
  const mascaras       = [];
  const xorResults     = [];

  for (let i = 0; i < bytes.length; i++) {
    const mascara  = (p1Reconstruida * (i + 1)) % 256;
    mascaras.push(mascara);
    resultado[i]   = bytes[i] ^ mascara;
    xorResults.push(resultado[i]);
  }

  const textDescifrado = resultado.toString('utf8');

  // ── Imprimir proceso completo en consola ─────────────────────────────────

  const DIV  = '='.repeat(62);
  const div2 = '-'.repeat(62);

  console.log('\n' + DIV);
  console.log('  PROCESO DE AUTENTICACION POLY-NUM');
  console.log(DIV);
  console.log(`  Usuario           : ${usuario}`);
  console.log(`  Hex recibido      : ${hexCifrado}`);
  console.log(`  Longitud (bytes)  : ${bytes.length}`);
  console.log(div2);

  // Etapa 1: clave publica recibida
  console.log('');
  console.log('  [Etapa 1] Clave publica entregada al cliente:');
  console.log(`    P1 = ${clavePublica}  (se comparte con el cliente)`);

  // Etapa 2: el cliente cifraba — se muestra lo recibido
  console.log('');
  console.log('  [Etapa 2] El cliente cifro localmente con P1:');
  console.log(`    mask_i = (P1 * (i+1)) mod 256`);
  console.log(`    C_i    = M_i XOR mask_i`);
  console.log(`    Hex transmitido: ${hexCifrado}`);
  console.log('    (La contrasena en texto plano NUNCA viajo por la red)');

  // Etapa 3: transmision
  console.log('');
  console.log('  [Etapa 3] Datos recibidos via POST /autenticar:');
  console.log(`    usuario         = "${usuario}"`);
  console.log(`    passwordCifrado = "${hexCifrado}"`);

  // Etapa 4: descifrado byte a byte
  console.log('');
  console.log('  [Etapa 4] Descifrado en servidor:');
  console.log(`    Clave privada   : s=${s}, k=${k}  [SECRETO]`);
  console.log(`    P1 reconstruida : P(${s}, 1+${k}) = P(${s}, ${1+k}) = ${p1Reconstruida}`);
  console.log(`    Formula         : M_i = C_i XOR mask_i`);
  console.log('');
  console.log('  ' + div2.slice(2));

  // Cabecera de la tabla
  const col = (v, w) => String(v).padStart(w);
  console.log(
    '  ' +
    col('Pos', 4) + '  ' +
    col('Hex', 6) + '  ' +
    col('Dec', 5) + '  ' +
    col('Mascara', 9) + '  ' +
    col('XOR', 5) + '  ' +
    'Char'
  );
  console.log('  ' + div2.slice(2));

  // Filas byte a byte
  const chars = [];
  for (const cp of textDescifrado) {
    const bl = Buffer.byteLength(cp, 'utf8');
    chars.push(cp);
    for (let j = 1; j < bl; j++) chars.push('');
  }

  for (let i = 0; i < bytes.length; i++) {
    const hexByte  = bytes[i].toString(16).toUpperCase().padStart(2, '0');
    const decByte  = bytes[i];
    const mascara  = mascaras[i];
    const xorVal   = xorResults[i];
    const caracter = chars[i] !== undefined ? `"${chars[i]}"` : '';

    console.log(
      '  ' +
      col(i + 1,   4) + '  ' +
      col(hexByte, 6) + '  ' +
      col(decByte, 5) + '  ' +
      col(mascara, 9) + '  ' +
      col(xorVal,  5) + '  ' +
      caracter
    );
  }

  console.log('  ' + div2.slice(2));
  console.log(`  Contrasena descifrada : "${textDescifrado}"`);

  return textDescifrado;
}

// ---------------------------------------------------------------------------
//  UTILIDADES HTTP
// ---------------------------------------------------------------------------

function parsearBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', f => {
      body += f.toString();
      if (body.length > 4096) reject(new Error('Payload demasiado grande'));
    });
    req.on('end', () => {
      try { resolve(JSON.parse(body)); }
      catch { reject(new Error('JSON invalido')); }
    });
    req.on('error', reject);
  });
}

function responder(res, codigo, datos) {
  res.writeHead(codigo, {
    'Content-Type'                : 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin' : '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'X-Content-Type-Options'      : 'nosniff'
  });
  res.end(JSON.stringify(datos, null, 2));
}

function ts() {
  return new Date().toLocaleTimeString('es-PE', { hour12: false });
}

// ---------------------------------------------------------------------------
//  BANNER DE INICIO
// ---------------------------------------------------------------------------

const DIV_BANNER = '='.repeat(52);
console.log('\n' + DIV_BANNER);
console.log('       SERVIDOR BANCARIO  --  POLY-NUM v1.1');
console.log('   Escuela de Ingenieria de Sistemas  UCSM');
console.log(DIV_BANNER);
console.log('');
console.log('  Clave privada : s=' + clavePrivada.s + ', k=' + clavePrivada.k + '  [SECRETO]');
console.log('  Clave publica : P1 = ' + clavePublica + '  [PUBLICO]');
console.log('  Formula       : P(' + clavePrivada.s + ', 1+' + clavePrivada.k + ') = P(' + clavePrivada.s + ', ' + (1+clavePrivada.k) + ') = ' + clavePublica);
console.log('  Periodo T     : ' + infoDiagnostico.periodo + ' bytes  [256 / MCD(' + clavePublica + ', 256)]');
console.log('  Puerto        : ' + CONFIG.puerto);
console.log('');
console.log('  Avisos:');
infoDiagnostico.advertencias.forEach(a => console.log('    ' + a));

// ---------------------------------------------------------------------------
//  SERVIDOR HTTP
// ---------------------------------------------------------------------------

const servidor = http.createServer(async (req, res) => {

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin' : '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    return res.end();
  }

  const { method: m, url } = req;

  // ── GET /clave-publica ────────────────────────────────────────────────────
  if (m === 'GET' && url === '/clave-publica') {
    console.log(`\n  [${ts()}] GET /clave-publica -> P1=${clavePublica} enviado al cliente`);
    return responder(res, 200, {
      ok          : true,
      clavePublica,
      algoritmo   : 'POLY-NUM v1.1'
    });
  }

  // ── POST /autenticar ──────────────────────────────────────────────────────
  if (m === 'POST' && url === '/autenticar') {
    try {
      const body = await parsearBody(req);
      const { usuario, passwordCifrado, p1Cliente } = body;

      // Validaciones basicas
      if (!usuario || typeof usuario !== 'string') {
        return responder(res, 400, { ok: false, error: 'Campo usuario invalido' });
      }
      if (!passwordCifrado || typeof passwordCifrado !== 'string') {
        return responder(res, 400, { ok: false, error: 'Campo passwordCifrado invalido' });
      }
      if (passwordCifrado.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(passwordCifrado)) {
        return responder(res, 400, { ok: false, error: 'passwordCifrado no es hexadecimal valido' });
      }

      // Cuenta bloqueada
      if (estaBloqueado(usuario)) {
        console.log(`\n  [${ts()}] [BLOQUEADO] ${usuario} supero ${MAX_INTENTOS_FALLIDOS} intentos`);
        return responder(res, 429, { ok: false, error: 'Cuenta bloqueada temporalmente.' });
      }

      // Verificar P1 del cliente si fue enviada
      if (p1Cliente !== undefined && !verificarClavePublica(p1Cliente, clavePrivada)) {
        console.log(`\n  [${ts()}] [ALERTA] P1 incorrecta recibida: ${p1Cliente}`);
        return responder(res, 401, { ok: false, error: 'Clave publica no coincide con la emitida.' });
      }

      // ── DESCIFRADO CON LOG COMPLETO EN CONSOLA ──
      const passwordDescifrado = descifrarConLog(passwordCifrado, clavePrivada, usuario);

      // ── ETAPA 5: Verificacion ─────────────────────────────────────────────
      console.log('');
      console.log('  [Etapa 5] Verificacion contra base de datos:');

      if (!USUARIOS_BD.has(usuario)) {
        registrarFallo(usuario);
        console.log(`    Usuario "${usuario}" no existe.`);
        console.log('    Resultado: ACCESO DENEGADO');
        console.log('='.repeat(62) + '\n');
        return responder(res, 401, { ok: false, error: 'Credenciales incorrectas.' });
      }

      const passwordReal = USUARIOS_BD.get(usuario);
      console.log(`    BD almacena        : "${passwordReal}"`);
      console.log(`    Descifrado recibido: "${passwordDescifrado}"`);

      if (passwordDescifrado !== passwordReal) {
        registrarFallo(usuario);
        console.log(`    Coinciden          : NO`);
        console.log('    Resultado          : ACCESO DENEGADO -- HTTP 401');
        console.log('='.repeat(62) + '\n');
        return responder(res, 401, { ok: false, error: 'Credenciales incorrectas.' });
      }

      // Autenticacion exitosa
      registroIntentos.delete(usuario);
      const token = Buffer.from(`${usuario}:${Date.now()}`).toString('base64');

      console.log(`    Coinciden          : SI`);
      console.log(`    Token emitido      : ${token}`);
      console.log('    Resultado          : AUTENTICADO -- HTTP 200');
      console.log('='.repeat(62) + '\n');

      return responder(res, 200, {
        ok      : true,
        mensaje : `Bienvenido, ${usuario}`,
        token,
        algoritmo: 'POLY-NUM v1.1'
      });

    } catch (err) {
      console.log(`\n  [ERROR] ${err.message}`);
      return responder(res, 500, { ok: false, error: 'Error interno del servidor.' });
    }
  }

  // ── GET / ─────────────────────────────────────────────────────────────────
  if (m === 'GET' && url === '/') {
    return responder(res, 200, {
      sistema  : 'POLY-NUM Banking Server v1.1',
      endpoints: {
        'GET  /clave-publica': 'Obtener P1',
        'POST /autenticar'   : 'Autenticar credenciales cifradas'
      }
    });
  }

  responder(res, 404, { ok: false, error: `Endpoint no encontrado: ${m} ${url}` });
});

// ---------------------------------------------------------------------------
//  INICIAR
// ---------------------------------------------------------------------------

servidor.listen(CONFIG.puerto, () => {
  console.log('\n' + '-'.repeat(52));
  console.log('  Servidor listo en http://localhost:' + CONFIG.puerto);
  console.log('  Abre: cliente_web/index.html en el navegador');
  console.log('  Usuarios: jperez, mgarcia, admin');
  console.log('-'.repeat(52) + '\n');
});

servidor.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    process.stderr.write(`\n[ERROR] Puerto ${CONFIG.puerto} en uso. Usa PORT=3001 node src/servidor.js\n`);
  } else {
    process.stderr.write(`\n[ERROR] ${err.message}\n`);
  }
  process.exit(1);
});
