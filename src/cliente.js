'use strict';

/**
 * @fileoverview cliente.js — Aplicacion cliente bancaria POLY-NUM
 *
 * Simula la aplicacion del usuario que implementa el protocolo POLY-NUM
 * de cinco etapas para autenticacion remota segura:
 *
 *   Etapa 1 — GET /clave-publica   : solicitar P1 al servidor
 *   Etapa 2 — Cifrado LOCAL        : cifrar contrasena con P1 en el dispositivo
 *   Etapa 3 — POST /autenticar     : transmitir credenciales cifradas
 *   Etapa 4 — Descifrado (servidor): transparente para el cliente
 *   Etapa 5 — Respuesta            : recibir token de sesion o rechazo
 *
 * Propiedad de seguridad demostrada:
 *   La contrasena en texto plano NUNCA abandona el dispositivo cliente.
 *   Solo viaja el texto cifrado en representacion hexadecimal.
 *
 * Instrucciones de ejecucion:
 *   1. node src/servidor.js   (terminal separada)
 *   2. node src/cliente.js
 *
 * @version 1.1.0
 * @authors Baldarrago Samatelo, Piero
 *          De los Rios Peralta, Jean Mael
 *          Guerra Huanaco, Keny Russell
 *          Sayritupac, Asqui Jeampier
 * @institution Escuela Profesional de Ingenieria de Sistemas — UCSM
 */

const http    = require('http');
const { cifrar } = require('./polynum');

// ---------------------------------------------------------------------------
//  CONFIGURACION DEL CLIENTE
// ---------------------------------------------------------------------------

const CONFIG_SERVIDOR = {
  host   : 'localhost',
  puerto : parseInt(process.env.PORT, 10) || 3000,
  timeout: 5000
};

// ---------------------------------------------------------------------------
//  UTILIDADES HTTP
// ---------------------------------------------------------------------------

/**
 * Realiza una peticion GET al servidor y retorna el cuerpo JSON parseado.
 *
 * @param {string} ruta - Ruta del endpoint.
 * @returns {Promise<{status: number, body: Object}>}
 */
function peticionGET(ruta) {
  return new Promise((resolve, reject) => {
    const opciones = {
      hostname: CONFIG_SERVIDOR.host,
      port    : CONFIG_SERVIDOR.puerto,
      path    : ruta,
      method  : 'GET',
      timeout : CONFIG_SERVIDOR.timeout
    };

    const req = http.request(opciones, res => {
      let data = '';
      res.on('data', fragmento => { data += fragmento; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          reject(new Error('La respuesta del servidor no es JSON valido'));
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(
        `Timeout: el servidor no respondio en ${CONFIG_SERVIDOR.timeout} ms`
      ));
    });

    req.on('error', err => {
      if (err.code === 'ECONNREFUSED') {
        reject(new Error(
          `Conexion rechazada en localhost:${CONFIG_SERVIDOR.puerto}. ` +
          'Verifique que el servidor este en ejecucion: node src/servidor.js'
        ));
      } else {
        reject(err);
      }
    });

    req.end();
  });
}

/**
 * Realiza una peticion POST con cuerpo JSON al servidor y retorna
 * el cuerpo JSON de la respuesta.
 *
 * @param {string} ruta  - Ruta del endpoint.
 * @param {Object} body  - Objeto a enviar como JSON.
 * @returns {Promise<{status: number, body: Object}>}
 */
function peticionPOST(ruta, body) {
  return new Promise((resolve, reject) => {
    const payload  = JSON.stringify(body);
    const opciones = {
      hostname: CONFIG_SERVIDOR.host,
      port    : CONFIG_SERVIDOR.puerto,
      path    : ruta,
      method  : 'POST',
      timeout : CONFIG_SERVIDOR.timeout,
      headers : {
        'Content-Type'  : 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    };

    const req = http.request(opciones, res => {
      let data = '';
      res.on('data', fragmento => { data += fragmento; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          reject(new Error('La respuesta del servidor no es JSON valido'));
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Timeout en POST ${ruta}`));
    });

    req.on('error', err => {
      if (err.code === 'ECONNREFUSED') {
        reject(new Error(
          'Conexion rechazada. Verifique que el servidor este en ejecucion: ' +
          'node src/servidor.js'
        ));
      } else {
        reject(err);
      }
    });

    req.write(payload);
    req.end();
  });
}

// ---------------------------------------------------------------------------
//  PROTOCOLO DE AUTENTICACION POLY-NUM (5 ETAPAS)
// ---------------------------------------------------------------------------

/**
 * Ejecuta el protocolo completo de autenticacion POLY-NUM para un par
 * de credenciales dado.
 *
 * @param {string} usuario   - Nombre de usuario.
 * @param {string} password  - Contrasena en texto plano (permanece en memoria local).
 * @returns {Promise<Object>} Cuerpo de la respuesta del servidor.
 */
async function autenticarUsuario(usuario, password) {
  const linea = '-'.repeat(50);
  console.log('');
  console.log(linea);
  console.log(`  Autenticando usuario: ${usuario}`);
  console.log(linea);

  // ETAPA 1 — Solicitar clave publica al servidor
  console.log('');
  console.log('  [Etapa 1] Solicitando clave publica P1 al servidor...');
  const respClave = await peticionGET('/clave-publica');

  if (respClave.status !== 200 || !respClave.body.ok) {
    throw new Error(
      `El servidor no proporciono la clave publica: ${respClave.body.error}`
    );
  }

  const p1 = respClave.body.clavePublica;
  if (!Number.isInteger(p1) || p1 <= 0) {
    throw new Error(`Clave publica invalida recibida del servidor: ${p1}`);
  }
  console.log(`           P1 recibida = ${p1}`);

  // ETAPA 2 — Cifrado LOCAL de la contrasena
  // La contrasena se cifra en el dispositivo del cliente.
  // El texto plano NUNCA se transmite por la red.
  console.log('');
  console.log('  [Etapa 2] Cifrando contrasena localmente con POLY-NUM...');
  console.log(`           Contrasena original : "${password}"`);

  const { cifrado, mascaras, longitud, periodo } = cifrar(password, p1);

  console.log(`           Texto cifrado (hex) : ${cifrado}`);
  console.log(`           Mascaras aplicadas  : [${mascaras.join(', ')}]`);
  console.log(`           Longitud en bytes   : ${longitud}`);
  console.log(`           Periodo de mascara  : T = ${periodo} bytes`);

  if (longitud > periodo) {
    console.log(
      `           [AVISO] Longitud (${longitud}) supera el periodo (${periodo}): ` +
      'el patron de mascara se repite.'
    );
  }

  console.log('           La contrasena NUNCA viaja en texto plano.');

  // ETAPA 3 — Transmision de credenciales cifradas
  console.log('');
  console.log('  [Etapa 3] Enviando credenciales cifradas al servidor...');
  const respAuth = await peticionPOST('/autenticar', {
    usuario,
    passwordCifrado: cifrado,
    p1Cliente      : p1
  });

  // ETAPA 5 — Procesar respuesta del servidor
  console.log('');
  console.log('  [Etapa 5] Respuesta del servidor:');
  if (respAuth.status === 200 && respAuth.body.ok) {
    console.log(`           [OK] ${respAuth.body.mensaje}`);
    console.log(`           Token de sesion: ${respAuth.body.token}`);
  } else {
    console.log(`           [ERROR HTTP ${respAuth.status}] ${respAuth.body.error}`);
  }

  return respAuth.body;
}

// ---------------------------------------------------------------------------
//  DEMOSTRACION DE CASOS DE USO
// ---------------------------------------------------------------------------

async function demo() {
  console.log('');
  console.log('+==============================================+');
  console.log('|       CLIENTE BANCARIO  --  POLY-NUM        |');
  console.log('|   Escuela de Ingenieria de Sistemas  UCSM   |');
  console.log('+==============================================+');
  console.log('');
  console.log('  Iniciando demostracion del protocolo de autenticacion...');

  const esperar = ms => new Promise(res => setTimeout(res, ms));

  try {
    // Caso 1: Credenciales correctas
    console.log('\n== CASO 1: Credenciales validas (jperez) ==');
    await autenticarUsuario('jperez', 'Banc@2024');
    await esperar(600);

    // Caso 2: Contrasena incorrecta
    console.log('\n== CASO 2: Contrasena incorrecta (mgarcia) ==');
    await autenticarUsuario('mgarcia', 'clavemalaeee');
    await esperar(600);

    // Caso 3: Segundo usuario valido
    console.log('\n== CASO 3: Credenciales validas (admin) ==');
    await autenticarUsuario('admin', 'Admin!2025');
    await esperar(600);

    // Caso 4: Usuario inexistente con contrasena UTF-8
    console.log('\n== CASO 4: Usuario inexistente con caracteres UTF-8 ==');
    await autenticarUsuario('rlopez', 'contrasenaUnica#1');

  } catch (err) {
    process.stderr.write(`\n  [ERROR] ${err.message}\n`);
    process.exit(1);
  }

  console.log('');
  console.log('  Demostracion finalizada.');
  console.log('');
}

demo();
