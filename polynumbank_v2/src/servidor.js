'use strict';

/**
 * @fileoverview servidor.js — Backend bancario POLY-NUM
 *
 * Simula el servidor de un sistema de autenticacion remota bancaria
 * que implementa el protocolo POLY-NUM de cinco etapas:
 *
 *   Etapa 1 — GET  /clave-publica  : emite P1 al cliente
 *   Etapa 4 — POST /autenticar     : descifra credenciales y autentica
 *
 * Consideraciones de produccion (fuera del alcance del prototipo):
 *   - Contrasenas almacenadas como hashes Argon2id o bcrypt.
 *   - Parametros (s, k) cargados desde variables de entorno o HSM.
 *   - Limitacion de intentos con Redis (rate limiting).
 *   - Nonce de sesion para eliminar el determinismo del cifrado.
 *   - HTTPS obligatorio en capa de transporte.
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
 * @institution Escuela Profesional de Ingenieria de Sistemas — UCSM
 */

const http = require('http');
const {
  generarClaves,
  descifrar,
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
//  NOTA ACADEMICA: En produccion, almacenar unicamente hashes irreversibles
//  (Argon2id recomendado por NIST SP 800-63B). Las contrasenas en texto
//  plano se incluyen aqui exclusivamente con fines demostrativos.
// ---------------------------------------------------------------------------

const USUARIOS_BD = new Map([
  ['jperez',  'Banc@2024'],
  ['mgarcia', 'Seguro#99'],
  ['admin',   'Admin!2025']
]);

// ---------------------------------------------------------------------------
//  CONTROL DE INTENTOS FALLIDOS (en memoria, solo para demostracion)
//  En produccion: Redis con TTL, persistencia y notificaciones de alerta.
// ---------------------------------------------------------------------------

const registroIntentos       = new Map();
const MAX_INTENTOS_FALLIDOS  = 5;
const VENTANA_BLOQUEO_MS     = 60_000;  // 1 minuto

/**
 * Registra un intento fallido para el usuario indicado y retorna si
 * la cuenta queda bloqueada.
 *
 * @param {string} usuario
 * @returns {boolean} true si la cuenta esta bloqueada tras este intento.
 */
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

/**
 * Indica si el usuario esta actualmente bloqueado.
 *
 * @param {string} usuario
 * @returns {boolean}
 */
function estaBloqueado(usuario) {
  const entrada = registroIntentos.get(usuario);
  if (!entrada) return false;
  if (Date.now() - entrada.desde > VENTANA_BLOQUEO_MS) return false;
  return entrada.intentos > MAX_INTENTOS_FALLIDOS;
}

// ---------------------------------------------------------------------------
//  UTILIDADES HTTP
// ---------------------------------------------------------------------------

/**
 * Lee y parsea el cuerpo JSON de una peticion HTTP entrante.
 * Limita el tamaño del payload a 4096 bytes para prevenir ataques
 * de payload oversized.
 *
 * @param {http.IncomingMessage} req
 * @returns {Promise<Object>}
 */
function parsearBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', fragmento => {
      body += fragmento.toString();
      if (body.length > 4096) {
        reject(new Error('Payload demasiado grande (limite: 4096 bytes)'));
      }
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error('El cuerpo de la peticion no es JSON valido'));
      }
    });
    req.on('error', reject);
  });
}

/**
 * Envia una respuesta JSON al cliente con los encabezados de seguridad
 * minimos recomendados.
 *
 * @param {http.ServerResponse} res
 * @param {number}              codigoHTTP - Codigo de estado HTTP.
 * @param {Object}              datos      - Objeto a serializar como JSON.
 */
function responder(res, codigoHTTP, datos) {
  res.writeHead(codigoHTTP, {
    'Content-Type'                : 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin' : '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'X-Content-Type-Options'      : 'nosniff',
    'X-Frame-Options'             : 'DENY'
  });
  res.end(JSON.stringify(datos, null, 2));
}

/**
 * Retorna la hora actual formateada para los registros del servidor.
 * @returns {string}
 */
function timestamp() {
  return new Date().toLocaleTimeString('es-PE', { hour12: false });
}

// ---------------------------------------------------------------------------
//  BANNER DE INICIO
// ---------------------------------------------------------------------------

console.log('');
console.log('+==============================================+');
console.log('|       SERVIDOR BANCARIO  --  POLY-NUM       |');
console.log('|   Escuela de Ingenieria de Sistemas  UCSM   |');
console.log('+==============================================+');
console.log('');
console.log(`  Clave privada : s=${clavePrivada.s}, k=${clavePrivada.k}`);
console.log(`  Clave publica : P1 = ${clavePublica}`);
console.log(`  Periodo T     : ${infoDiagnostico.periodo} bytes`);
console.log(`  Puerto        : ${CONFIG.puerto}`);
console.log('');
console.log('  Avisos del modo de demostracion:');
infoDiagnostico.advertencias.forEach(aviso => console.log(`    ${aviso}`));

// ---------------------------------------------------------------------------
//  SERVIDOR HTTP
// ---------------------------------------------------------------------------

const servidor = http.createServer(async (req, res) => {

  // Preflight CORS
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin' : '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age'      : '86400'
    });
    return res.end();
  }

  const { method: metodo, url } = req;
  console.log(`  [${timestamp()}] ${metodo} ${url}`);

  // --------------------------------------------------------------------------
  //  ETAPA 1 | GET /clave-publica
  //  El servidor emite P1. El cliente usara este valor para cifrar
  //  su contrasena localmente. P1 nunca revela s ni k.
  // --------------------------------------------------------------------------
  if (metodo === 'GET' && url === '/clave-publica') {
    console.log(`  -> Emitiendo clave publica P1=${clavePublica} al cliente`);
    return responder(res, 200, {
      ok          : true,
      clavePublica,
      algoritmo   : 'POLY-NUM v1.1',
      descripcion : [
        `Clave publica P1 = P(${clavePrivada.s}, 1+${clavePrivada.k}) = ${clavePublica}.`,
        'Use P1 para cifrar su contrasena: C_i = M_i XOR ((P1 * (i+1)) mod 256).',
        'La contrasena en texto plano nunca debe abandonar el dispositivo cliente.'
      ].join(' ')
    });
  }

  // --------------------------------------------------------------------------
  //  ETAPAS 4-5 | POST /autenticar
  //  El servidor recibe credenciales cifradas, descifra con (s, k),
  //  verifica contra la base de datos y emite un token de sesion.
  // --------------------------------------------------------------------------
  if (metodo === 'POST' && url === '/autenticar') {
    try {
      const body = await parsearBody(req);
      const { usuario, passwordCifrado, p1Cliente } = body;

      // Validacion de campos requeridos
      if (!usuario || typeof usuario !== 'string') {
        return responder(res, 400, {
          ok   : false,
          error: 'Campo requerido faltante o invalido: usuario'
        });
      }
      if (!passwordCifrado || typeof passwordCifrado !== 'string') {
        return responder(res, 400, {
          ok   : false,
          error: 'Campo requerido faltante o invalido: passwordCifrado'
        });
      }
      if (passwordCifrado.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(passwordCifrado)) {
        return responder(res, 400, {
          ok   : false,
          error: 'passwordCifrado debe ser una cadena hexadecimal valida de longitud par'
        });
      }

      // Control de acceso: cuenta bloqueada por exceso de intentos
      if (estaBloqueado(usuario)) {
        console.log(
          `  [BLOQUEADO] ${usuario} — excedio ${MAX_INTENTOS_FALLIDOS} intentos fallidos`
        );
        return responder(res, 429, {
          ok   : false,
          error: 'Cuenta temporalmente bloqueada por exceso de intentos fallidos.'
        });
      }

      // Verificacion opcional de P1 del cliente
      if (p1Cliente !== undefined) {
        if (!Number.isInteger(p1Cliente)) {
          return responder(res, 400, {
            ok   : false,
            error: 'p1Cliente debe ser un entero'
          });
        }
        if (!verificarClavePublica(p1Cliente, clavePrivada)) {
          console.log(
            `  [ALERTA] P1 incorrecta recibida: ${p1Cliente} != ${clavePublica}. ` +
            'Posible ataque de repeticion o configuracion incorrecta del cliente.'
          );
          return responder(res, 401, {
            ok   : false,
            error: 'La clave publica no coincide con la emitida por este servidor.'
          });
        }
      }

      // Descifrado de la contrasena
      console.log(`  -> Texto cifrado recibido : ${passwordCifrado}`);
      let passwordDescifrado;
      try {
        passwordDescifrado = descifrar(passwordCifrado, clavePrivada);
      } catch (errDescifrado) {
        console.log(`  -> Error en descifrado: ${errDescifrado.message}`);
        return responder(res, 400, {
          ok   : false,
          error: 'No se pudo procesar el texto cifrado recibido.'
        });
      }
      console.log(`  -> Contrasena descifrada  : ${passwordDescifrado}`);

      // Verificacion del usuario en la base de datos
      if (!USUARIOS_BD.has(usuario)) {
        registrarFallo(usuario);
        // Respuesta generica para no revelar si el usuario existe (user enumeration)
        return responder(res, 401, { ok: false, error: 'Credenciales incorrectas.' });
      }

      const passwordReal = USUARIOS_BD.get(usuario);

      // Comparacion de contrasenas
      // NOTA DE PRODUCCION: usar crypto.timingSafeEqual sobre hashes para
      // prevenir ataques de tiempo (timing attacks).
      if (passwordDescifrado !== passwordReal) {
        console.log(`  -> Contrasena incorrecta para "${usuario}"`);
        const bloqueado = registrarFallo(usuario);
        if (bloqueado) {
          console.log(`  -> [CUENTA BLOQUEADA] ${usuario}`);
        }
        return responder(res, 401, { ok: false, error: 'Credenciales incorrectas.' });
      }

      // Autenticacion exitosa
      registroIntentos.delete(usuario);

      // Token de sesion basico (en produccion: JWT firmado con RS256 y expiracion)
      const token = Buffer.from(`${usuario}:${Date.now()}`).toString('base64');
      console.log(`  -> [AUTENTICADO] ${usuario} | Token: ${token}`);

      return responder(res, 200, {
        ok       : true,
        mensaje  : `Bienvenido, ${usuario}`,
        token,
        algoritmo: 'POLY-NUM v1.1',
        nota     : [
          'Token de sesion generado (demostracion).',
          'En produccion: JWT firmado con RS256, expiracion y rotacion de claves.'
        ].join(' ')
      });

    } catch (err) {
      console.log(`  -> Error interno: ${err.message}`);
      return responder(res, 500, {
        ok   : false,
        error: 'Error interno del servidor. Intente nuevamente.'
      });
    }
  }

  // --------------------------------------------------------------------------
  //  GET / — Informacion del sistema
  // --------------------------------------------------------------------------
  if (metodo === 'GET' && url === '/') {
    return responder(res, 200, {
      sistema   : 'POLY-NUM Banking Authentication Server',
      version   : '1.1.0',
      algoritmo : 'POLY-NUM — Cifrado asimetrico basado en numeros poligonales',
      endpoints : {
        'GET  /clave-publica': 'Etapa 1: obtener P1 para cifrar la contrasena localmente',
        'POST /autenticar'   : 'Etapas 4-5: enviar credenciales cifradas y recibir token'
      },
      parametrosDemostracion: {
        rangoS       : `[${constantes.S_MIN}, ${constantes.S_MAX}]`,
        rangoK       : `[${constantes.K_MIN}, ${constantes.K_MAX}]`,
        espacioClaves: (constantes.S_MAX - constantes.S_MIN + 1) *
                       (constantes.K_MAX - constantes.K_MIN + 1),
        advertencia  : 'Configuracion solo para demostracion academica. No usar en produccion.'
      }
    });
  }

  // 404 — Endpoint no encontrado
  responder(res, 404, {
    ok   : false,
    error: `Endpoint no encontrado: ${metodo} ${url}`
  });
});

// ---------------------------------------------------------------------------
//  INICIAR SERVIDOR
// ---------------------------------------------------------------------------

servidor.listen(CONFIG.puerto, () => {
  console.log('');
  console.log(`  Servidor listo en http://localhost:${CONFIG.puerto}`);
  console.log('  Usuarios de demostracion: jperez, mgarcia, admin');
  console.log('');
});

servidor.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    process.stderr.write(
      `\n[ERROR] Puerto ${CONFIG.puerto} ya esta en uso.\n` +
      `  Solucion: PORT=${CONFIG.puerto + 1} node src/servidor.js\n`
    );
  } else {
    process.stderr.write(`\n[ERROR] Error del servidor: ${err.message}\n`);
  }
  process.exit(1);
});
