import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';

/**
 * @typedef {Object} MessageAuth
 * @property {string} username - The authentication username.
 * @property {string} password - The authentication password.
 */

/**
 * @typedef {Object} AtxpMessage
 * @property {number} type - The message type code (from MT enum).
 * @property {Buffer} data - The payload binary buffer data.
 * @property {MessageAuth} auth - The authentication payload.
 * @property {string} [filename] - Optional filename tracking for Document type.
 */

/**
 * Message Type (MT) enumeration for ATXP frames.
 * @enum {number}
 */
export const MT = {
  URL: 0,
  DOCUMENT: 1,
  NOTIFICATION: 2,
};

/**
 * Response Code enumeration sent by ATXP servers.
 * @enum {number}
 */
export const ResponseCode = {
  OK: 0,
  ERROR: 1,
  UNAUTHORIZED: 2,
};

/**
 * Error thrown when an invalid or malformed ATXP packet is processed.
 * @type {Error}
 */
export const ErrInvalidFormat = new Error('malformed atxp packet protocol');

/**
 * Class representing optional authentication metadata, mimicking box.Optional behavior.
 */
export class AuthData {
  /**
   * @param {Record<string, any>|null|undefined} value 
   */
  constructor(value) {
    this.value = value || null;
  }

  /**
   * Checks if the authentication optional context data structure contains a null state value.
   * @returns {boolean} True if no inner metadata exists.
   */
  isEmpty() {
    return this.value === null;
  }

  /**
   * Extracts the underlying map structure from the optional container box.
   * @returns {Record<string, any>|null} The underlying data object state map reference.
   */
  get() {
    return this.value;
  }
}

/**
 * Converts a numeric Message Type (MT) enum to its equivalent string representation.
 * @param {number} messageType - The message type numeric identifier.
 * @returns {string} The string representation ('URL', 'Document', 'Notification', or 'UNKNOWN').
 */
export function typeToString(messageType) {
  switch (messageType) {
    case MT.URL:
      return 'URL';
    case MT.DOCUMENT:
      return 'Document';
    case MT.NOTIFICATION:
      return 'Notification';
    default:
      return 'UNKNOWN';
  }
}

/**
 * Converts a valid ATXP message type string back into its numeric enum equivalent.
 * @param {string} str - The type string pattern.
 * @returns {number} The corresponding MT enum number, or -1 if unrecognized.
 */
export function stringToType(str) {
  switch (str) {
    case 'URL':
      return MT.URL;
    case 'Document':
      return MT.DOCUMENT;
    case 'Notification':
      return MT.NOTIFICATION;
    default:
      return -1;
  }
}

/**
 * Serializes a structured message object into a single raw Buffer matching the ATXP specification.
 * @param {AtxpMessage} msg - The message container to serialize.
 * @throws {Error} Throws ErrInvalidFormat if the message object is missing.
 * @returns {Buffer} The constructed raw byte buffer stream ready to be transmitted over the wire.
 */
export function serialize(msg) {
  if (!msg) {
    throw ErrInvalidFormat;
  }

  const typeStr = typeToString(msg.type);
  const dataBuffer = msg.data ? Buffer.from(msg.data) : Buffer.alloc(0);
  const username = msg.auth?.username || '';
  const password = msg.auth?.password || '';
  const filenamePart = (msg.type === MT.DOCUMENT && msg.filename) ? `::${msg.filename}` : '';

  const part1 = Buffer.from(`${typeStr}\t\t`);
  const part2 = Buffer.from(`\t\tAuth:${username}::${password}${filenamePart}\n\n`);

  return Buffer.concat([part1, dataBuffer, part2]);
}

/**
 * Deserializes a raw string frame buffer back into a structured ATXP message entity.
 * @param {string} bufferStr - The complete raw package frame string to evaluate.
 * @throws {Error} Throws ErrInvalidFormat if elements are out of bounds or parsing fails.
 * @returns {AtxpMessage} The parsed JavaScript message representation object.
 */
export function deserialize(bufferStr) {
  if (!bufferStr) {
    throw ErrInvalidFormat;
  }

  const typePartIdx = bufferStr.indexOf('\t\t');
  if (typePartIdx === -1) {
    throw ErrInvalidFormat;
  }
  const typeStr = bufferStr.substring(0, typePartIdx);

  const authPartIdx = bufferStr.indexOf('\t\tAuth:');
  if (authPartIdx === -1) {
    throw ErrInvalidFormat;
  }

  const dataStr = bufferStr.substring(typePartIdx + 2, authPartIdx);

  const tailIdx = bufferStr.indexOf('\n\n');
  if (tailIdx === -1) {
    throw ErrInvalidFormat;
  }

  const authStr = bufferStr.substring(authPartIdx + 7, tailIdx);
  const parts = authStr.split('::');
  if (parts.length < 2) {
    throw ErrInvalidFormat;
  }

  const username = parts[0];
  const password = parts[1];
  const type = stringToType(typeStr);
  const filename = (type === MT.DOCUMENT && parts.length > 2) ? parts[2] : undefined;

  return {
    type,
    data: Buffer.from(dataStr),
    auth: { username, password },
    filename
  };
}

/**
 * Reads data segments asynchronously from a connection stream until it identifies the ATXP closing payload delimiter (\n\n).
 * @param {net.Socket|tls.TLSSocket} conn - The active incoming network socket connection pipeline.
 * @returns {Promise<string>} Resolves with the accumulated raw frame string response.
 */
export function receive(conn) {
  return new Promise((resolve, reject) => {
    let bufferStr = '';

    function onData(chunk) {
      bufferStr += chunk.toString('utf8');
      if (bufferStr.endsWith('\n\n')) {
        cleanup();
        resolve(bufferStr);
      }
    }

    function onError(err) {
      cleanup();
      reject(err);
    }

    function onEnd() {
      cleanup();
      resolve(bufferStr);
    }

    function cleanup() {
      conn.removeListener('data', onData);
      conn.removeListener('error', onError);
      conn.removeListener('end', onEnd);
    }

    conn.on('data', onData);
    conn.on('error', onError);
    conn.on('end', onEnd);
  });
}

/**
 * Formats, packs, and writes an ATXP protocol message structure payload directly down a network link.
 * @param {net.Socket|tls.TLSSocket} conn - The destination data transportation channel socket.
 * @param {AtxpMessage} msg - The input structured data envelope framework.
 * @returns {Promise<number>} Resolves with total bytes successfully transmitted over the socket interface.
 */
export function send(conn, msg) {
  return new Promise((resolve, reject) => {
    try {
      const payload = serialize(msg);
      conn.write(payload, (err) => {
        if (err) return reject(err);
        resolve(payload.length);
      });
    } catch (err) {
      reject(err);
    }
  });
}

/**
 * Transmits an isolated ATXP standard code response back across the client node stream.
 * @param {net.Socket|tls.TLSSocket} conn - The communication pipeline.
 * @param {number} responseCode - The response identifier (from ResponseCode enum).
 * @returns {Promise<number>} Resolves echoing back the provided input payload response code.
 */
export function sendResponse(conn, responseCode) {
  return new Promise((resolve, reject) => {
    const respStr = `RESP:${responseCode}\n\n`;
    conn.write(respStr, 'utf8', (err) => {
      if (err) return reject(err);
      resolve(responseCode);
    });
  });
}

/**
 * Blocks and handles ingestion parameters asynchronously awaiting a structured ATXP protocol status response code.
 * @param {net.Socket|tls.TLSSocket} conn - The reference socket target source stream.
 * @throws {Error} Throws ErrInvalidFormat if incoming format does not comply with regular matching guidelines.
 * @returns {Promise<number>} Resolves to the parsed protocol response code.
 */
export async function receiveResponse(conn) {
  const buffer = await receive(conn);
  if (!buffer) {
    return ResponseCode.ERROR;
  }

  const match = buffer.match(/^RESP:(\d+)\n\n$/);
  if (!match) {
    throw ErrInvalidFormat;
  }

  return parseInt(match[1], 10);
}

// --- CLIENT IMPLEMENTATION ---

/** Class representing an ATXP protocol Client interface. */
export class Client {
  /**
   * Create an ATXP Client.
   * @param {net.Socket|tls.TLSSocket} conn - An active client pipeline connection socket wrapper.
   * @param {string} username - Client access username identifier credentials.
   * @param {string} password - Client security pairing key passcode strings.
   */
  constructor(conn, username, password) {
    this.conn = conn;
    this.auth = { username, password };
  }

  /**
   * Dispatches a structured URL transmission frame over the pipeline wire connection.
   * @param {string} url - Target reference locator uniform sequence.
   * @returns {Promise<number>} Resolves to the specific response verification code returned by the server.
   */
  async sendURL(url) {
    const msg = {
      type: MT.URL,
      data: Buffer.from(url),
      auth: this.auth
    };
    await send(this.conn, msg);
    return receiveResponse(this.conn);
  }

  /**
   * Dispatches a dedicated Document binary buffer over the pipeline network connection with optional filename tracking.
   * @param {Buffer} documentBuffer - The document content payload package.
   * @param {string} [filename] - The original name of the document file.
   * @returns {Promise<number>} Resolves to the specific response verification code returned by the server.
   */
  async sendDocument(documentBuffer, filename) {
    const msg = {
      type: MT.DOCUMENT,
      data: documentBuffer,
      auth: this.auth,
      filename
    };
    await send(this.conn, msg);
    return receiveResponse(this.conn);
  }

  /**
   * Dispatches a structured text notification notification string component frame across the wire channel.
   * @param {string} message - Simple notification alert text description content.
   * @returns {Promise<number>} Resolves to the specific response verification code returned by the server.
   */
  async sendNotification(message) {
    const msg = {
      type: MT.NOTIFICATION,
      data: Buffer.from(message),
      auth: this.auth
    };
    await send(this.conn, msg);
    return receiveResponse(this.conn);
  }
}

// --- SERVER IMPLEMENTATION ---

/**
 * @typedef {Object} AuthResult
 * @property {boolean} authorized - True if validation matches.
 * @property {AuthData} data - Optional session details mapping data payload.
 */

/**
 * Callback definition for processing ATXP authentication checks.
 * @callback AuthCallback
 * @param {string} username - Extracted user security profile validation identity.
 * @param {string} password - Extracted user pairing authentication token verify keys.
 * @returns {AuthResult} Outlining matching verification and embedded structured metadata.
 */

/**
 * Callback definition for processing custom operational business logic message updates.
 * @callback HandlerCallback
 * @param {AtxpMessage} msg - The fully deserialized message structure.
 * @param {AuthData} authData - Optional session validation parameters container.
 * @returns {number} The evaluated exit ResponseCode logic flag value indicator to pass downstream.
 */

/** Class representing an ATXP protocol server layer engine daemon. */
export class Server {
  /**
   * Create an ATXP Server.
   * @param {AuthCallback} [authFn] - Optional validation function to check credentials per request.
   */
  constructor(authFn) {
    /** @type {Map<number, HandlerCallback>} */
    this.handlers = new Map();
    this.authFn = authFn;
    /** @type {net.Server|tls.Server|null} */
    this.server = null;
  }

  /**
   * Registers a callback mapping function handler to manage execution flows whenever a specified message type lands.
   * @param {number} messageType - The message category type lookup selector key (MT value).
   * @param {HandlerCallback} handler - Callback runtime logic execution block.
   */
  registerHandler(messageType, handler) {
    this.handlers.set(messageType, handler);
  }

  /**
   * Initialises the listener networking server configuration hooks across targeted processing socket boundaries.
   * @param {number} port - Network system access port number.
   * @param {boolean} [isTls=false] - Toggle TLS framing transport layers wrapper enforcement.
   * @param {tls.SecureContextOptions|null} [tlsOptions=null] - Explicit options details container mapping configuration files required for safe TLS environments.
   * @returns {Promise<net.Server|tls.Server>} The initialized and listening native Node.js server instance object.
   */
  listen(port, isTls = false, tlsOptions = null) {
    return new Promise((resolve, reject) => {
      const connectionHandler = (conn) => this.handleConnection(conn);

      if (isTls) {
        if (!tlsOptions) return reject(new Error('tls configuration cannot be nil'));
        this.server = tls.createServer(tlsOptions, connectionHandler);
      } else {
        this.server = net.createServer(connectionHandler);
      }

      this.server.listen(port, () => resolve(this.server));
      this.server.on('error', (err) => reject(err));
    });
  }

  /**
   * Asynchronously polls network socket pipes, validating connection flows, authenticating clients, and routing requests safely.
   * @param {net.Socket|tls.TLSSocket} conn - The freshly established operational target raw system input stream.
   * @returns {Promise<void>}
   */
  async handleConnection(conn) {
    try {
      while (true) {
        let rawMsg;
        try {
          rawMsg = await receive(conn);
        } catch {
          break;
        }

        if (!rawMsg) break;

        let msg;
        try {
          msg = deserialize(rawMsg);
        } catch {
          await sendResponse(conn, ResponseCode.ERROR);
          break;
        }

        let authData = new AuthData(null);

        if (this.authFn) {
          const { authorized, data } = this.authFn(msg.auth.username, msg.auth.password);
          if (!authorized) {
            await sendResponse(conn, ResponseCode.UNAUTHORIZED);
            break;
          }
          authData = data;
        }

        const handler = this.handlers.get(msg.type);
        if (!handler) {
          await sendResponse(conn, ResponseCode.ERROR);
          continue;
        }

        const code = handler(msg, authData);
        await sendResponse(conn, code);
      }
    } finally {
      conn.destroy();
    }
  }

  /**
   * Dismantles ongoing binding hooks cleanly shutting down network processes.
   * @returns {Promise<void>} Resolves when the underlying server is completely closed.
   */
  close() {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }
}

// --- HANDLERS VALIDATION ---

/**
 * Factory creating validation handlers dedicated to testing structural accuracy on incoming URL payloads.
 * @returns {HandlerCallback} A configured logic assertion handler validation middleware block.
 */
export function validateURLHandler() {
  return (msg, _authData) => {
    if (!msg.data || msg.data.length === 0) {
      return ResponseCode.ERROR;
    }
    const urlStr = msg.data.toString('utf8');
    if (!urlStr.startsWith('http://') && !urlStr.startsWith('https://')) {
      return ResponseCode.ERROR;
    }
    return ResponseCode.OK;
  };
}

/**
 * Factory creating validation handlers checking capacity limitations on incoming Document data frames.
 * @param {number} maxBytes - Absolute ceiling calculation constraint determining valid payload size restrictions.
 * @returns {HandlerCallback} A configured logic assertion handler validation middleware block.
 */
export function validateDocumentHandler(maxBytes) {
  return (msg, _authData) => {
    if (!msg.data || msg.data.length === 0 || msg.data.length > maxBytes) {
      return ResponseCode.ERROR;
    }
    return ResponseCode.OK;
  };
}

// =====================================================================
// ATXP V2 — secure layer (password-derived encryption, binary-safe framing)
// =====================================================================
//
// V2 encrypts every frame with AES-256-GCM under a key derived from a shared
// password via PBKDF2-HMAC-SHA256. The password is never transmitted; the GCM
// tag proves possession. Frames use a length-prefixed binary envelope, so any
// binary payload (PDFs, images) is carried losslessly. The wire layout is
// byte-identical to the Go implementation.

/** Sizing constants fixed by the chosen primitives. */
export const SALT_SIZE = 16;
export const NONCE_SIZE = 12;
export const KEY_SIZE = 32;
export const GCM_TAG_SIZE = 16;
export const LENGTH_PREFIX_SIZE = 4;
export const DEFAULT_KDF_ITERATIONS = 600000;
export const MAX_FRAME_SIZE_V2 = 1 << 24; // 16 MiB
export const PROTOCOL_VERSION_V2 = 2;
export const HANDSHAKE_MAGIC = 'ATXP2';
export const DEFAULT_IO_TIMEOUT_MS = 30000;

const HANDSHAKE_HEADER_SIZE = HANDSHAKE_MAGIC.length + 1 + SALT_SIZE; // 22
const KIND_MESSAGE = 0x01;
const KIND_RESPONSE = 0x02;

/** Sentinel errors for the V2 layer. */
export const ErrInvalidChecksum = new Error('atxp: decryption or authentication failed');
export const ErrFrameTooLarge = new Error('atxp: frame exceeds MaxFrameSizeV2');
export const ErrFrameTooSmall = new Error('atxp: frame smaller than minimum secure envelope');
export const ErrHandshake = new Error('atxp: handshake failed');
export const ErrWeakPassword = new Error('atxp: password must be non-empty');
export const ErrReplay = new Error('atxp: out-of-order or replayed frame');
export const ErrInvalidEnvelope = new Error('atxp: malformed v2 envelope');

/**
 * @typedef {Object} MT_V2
 * @property {string} name - Human-readable type name.
 * @property {number} code - Unique numeric routing identifier (uint32).
 * @property {string} description - Documentation of the type's purpose.
 */

/** @type {Map<number, MT_V2>} Registry of V2 message types, safe by single-thread. */
const registeredMTs = new Map([
  [MT.URL, { name: 'URL', code: MT.URL, description: 'Used for transmitting URLs across the network, it can be used to register a webhook.' }],
  [MT.DOCUMENT, { name: 'DOCUMENT', code: MT.DOCUMENT, description: 'Used for transferring files. Can be used for storage servers.' }],
  [MT.NOTIFICATION, { name: 'NOTIFICATION', code: MT.NOTIFICATION, description: 'Used to transmit JSON or events. Can be used in an event-driven architecture.' }],
]);

/**
 * Registers a new V2 message type. Returns false (registering nothing) when the
 * code is already in use.
 * @param {MT_V2} mt
 * @returns {boolean}
 */
export function newMT(mt) {
  if (registeredMTs.has(mt.code)) {
    return false;
  }
  registeredMTs.set(mt.code, mt);
  return true;
}

/**
 * Looks up a registered message type by code.
 * @param {number} code
 * @returns {MT_V2|undefined}
 */
export function lookupMT(code) {
  return registeredMTs.get(code);
}

/**
 * Resolves a message type code to its name, or 'UNKNOWN'.
 * @param {number} code
 * @returns {string}
 */
export function typeToStringV2(code) {
  const mt = registeredMTs.get(code);
  return mt ? mt.name : 'UNKNOWN';
}

/**
 * Resolves a message type name to its code, or -1 when unknown.
 * @param {string} name
 * @returns {number}
 */
export function stringToTypeV2(name) {
  for (const mt of registeredMTs.values()) {
    if (mt.name === name) return mt.code;
  }
  return -1;
}

/**
 * Derives a 32-byte AES-256 key from a password and salt via PBKDF2-HMAC-SHA256.
 * @param {string} password
 * @param {Buffer} salt
 * @param {number} iterations
 * @returns {Buffer}
 */
export function deriveKey(password, salt, iterations) {
  if (!Buffer.isBuffer(salt) || salt.length !== SALT_SIZE) {
    throw ErrHandshake;
  }
  const iter = iterations > 0 ? iterations : DEFAULT_KDF_ITERATIONS;
  return crypto.pbkdf2Sync(password, salt, iter, KEY_SIZE, 'sha256');
}

/** AES-256-GCM cipher producing the layout nonce || ciphertext || tag. */
export class GCMCipher {
  /** @param {Buffer} key 32-byte key. */
  constructor(key) {
    if (!Buffer.isBuffer(key) || key.length !== KEY_SIZE) {
      throw new Error('atxp: key must be 32 bytes for AES-256');
    }
    this.key = key;
  }

  /**
   * Encrypts plaintext with a fresh random nonce.
   * @param {Buffer} plaintext
   * @returns {Buffer} nonce || ciphertext || tag
   */
  seal(plaintext) {
    const nonce = crypto.randomBytes(NONCE_SIZE);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, nonce);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([nonce, ciphertext, tag]);
  }

  /**
   * Authenticates and decrypts a frame produced by seal().
   * @param {Buffer} frame nonce || ciphertext || tag
   * @returns {Buffer} plaintext
   * @throws {Error} ErrInvalidChecksum on any authentication failure.
   */
  open(frame) {
    if (frame.length < NONCE_SIZE + GCM_TAG_SIZE) {
      throw ErrFrameTooSmall;
    }
    const nonce = frame.subarray(0, NONCE_SIZE);
    const tag = frame.subarray(frame.length - GCM_TAG_SIZE);
    const ciphertext = frame.subarray(NONCE_SIZE, frame.length - GCM_TAG_SIZE);
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, nonce);
    decipher.setAuthTag(tag);
    try {
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      throw ErrInvalidChecksum;
    }
  }
}

function lengthPrefixed(buf) {
  const prefix = Buffer.alloc(LENGTH_PREFIX_SIZE);
  prefix.writeUInt32BE(buf.length, 0);
  return Buffer.concat([prefix, buf]);
}

/** Bounds-checked cursor over a decrypted envelope. */
class EnvelopeReader {
  constructor(buf) {
    this.b = buf;
    this.off = 0;
  }
  u8() {
    if (this.off + 1 > this.b.length) throw ErrInvalidEnvelope;
    return this.b[this.off++];
  }
  u32() {
    if (this.off + 4 > this.b.length) throw ErrInvalidEnvelope;
    const v = this.b.readUInt32BE(this.off);
    this.off += 4;
    return v;
  }
  u64() {
    if (this.off + 8 > this.b.length) throw ErrInvalidEnvelope;
    const v = this.b.readBigUInt64BE(this.off);
    this.off += 8;
    return Number(v);
  }
  field() {
    const n = this.u32();
    if (this.off + n > this.b.length) throw ErrInvalidEnvelope;
    const out = Buffer.from(this.b.subarray(this.off, this.off + n));
    this.off += n;
    return out;
  }
  done() {
    return this.off === this.b.length;
  }
}

/**
 * Encodes a message and sequence number into the V2 inner plaintext envelope.
 * @param {AtxpMessage} msg
 * @param {number} seq
 * @returns {Buffer}
 */
export function serializeV2(msg, seq) {
  if (!msg) throw ErrInvalidFormat;
  const payload = msg.data ? Buffer.from(msg.data) : Buffer.alloc(0);
  const username = Buffer.from(msg.auth?.username || '', 'utf8');
  const filename = Buffer.from(msg.filename || '', 'utf8');

  const head = Buffer.alloc(1 + 8 + 4);
  head.writeUInt8(KIND_MESSAGE, 0);
  head.writeBigUInt64BE(BigInt(seq), 1);
  head.writeUInt32BE(msg.type >>> 0, 9);

  return Buffer.concat([head, lengthPrefixed(payload), lengthPrefixed(username), lengthPrefixed(filename)]);
}

/**
 * Decodes a V2 message envelope.
 * @param {Buffer} plaintext
 * @returns {{ seq: number, msg: AtxpMessage }}
 */
export function deserializeV2(plaintext) {
  const r = new EnvelopeReader(plaintext);
  const kind = r.u8();
  if (kind !== KIND_MESSAGE) throw ErrInvalidEnvelope;
  const seq = r.u64();
  const code = r.u32();
  const payload = r.field();
  const username = r.field();
  const filename = r.field();
  if (!r.done()) throw ErrInvalidEnvelope;

  return {
    seq,
    msg: {
      type: code,
      data: payload,
      auth: { username: username.toString('utf8') },
      filename: filename.length ? filename.toString('utf8') : undefined,
    },
  };
}

function serializeResponseV2(code, seq) {
  const buf = Buffer.alloc(1 + 8 + 4);
  buf.writeUInt8(KIND_RESPONSE, 0);
  buf.writeBigUInt64BE(BigInt(seq), 1);
  buf.writeUInt32BE(code >>> 0, 9);
  return buf;
}

function deserializeResponseV2(plaintext) {
  const r = new EnvelopeReader(plaintext);
  const kind = r.u8();
  if (kind !== KIND_RESPONSE) throw ErrInvalidEnvelope;
  const seq = r.u64();
  const code = r.u32();
  if (!r.done()) throw ErrInvalidEnvelope;
  return { code, seq };
}

/**
 * Buffers a Node socket so callers can read exact byte counts and write frames.
 */
class FramedConn {
  /** @param {net.Socket|tls.TLSSocket} socket */
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.waiters = [];
    this.ended = false;
    this.error = null;

    socket.on('data', (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this._pump();
    });
    socket.on('end', () => { this.ended = true; this._pump(); });
    socket.on('close', () => { this.ended = true; this._pump(); });
    socket.on('error', (err) => { this.error = err; this._pump(); });
  }

  _pump() {
    while (this.waiters.length) {
      const w = this.waiters[0];
      if (this.buffer.length >= w.n) {
        const out = Buffer.from(this.buffer.subarray(0, w.n));
        this.buffer = this.buffer.subarray(w.n);
        this.waiters.shift();
        w.resolve(out);
      } else if (this.error) {
        this.waiters.shift();
        w.reject(this.error);
      } else if (this.ended) {
        this.waiters.shift();
        w.reject(new Error('atxp: unexpected EOF'));
      } else {
        break;
      }
    }
  }

  /**
   * @param {number} n
   * @returns {Promise<Buffer>}
   */
  readExactly(n) {
    return new Promise((resolve, reject) => {
      this.waiters.push({ n, resolve, reject });
      this._pump();
    });
  }

  /**
   * @param {Buffer} buf
   * @returns {Promise<number>}
   */
  write(buf) {
    return new Promise((resolve, reject) => {
      this.socket.write(buf, (err) => (err ? reject(err) : resolve(buf.length)));
    });
  }

  destroy() {
    this.socket.destroy();
  }
}

async function readFrame(framed, cipher, maxFrameSize = MAX_FRAME_SIZE_V2) {
  const lenBuf = await framed.readExactly(LENGTH_PREFIX_SIZE);
  const n = lenBuf.readUInt32BE(0);
  if (n > maxFrameSize) throw ErrFrameTooLarge;
  if (n < NONCE_SIZE + GCM_TAG_SIZE) throw ErrFrameTooSmall;
  const sealed = await framed.readExactly(n);
  return cipher.open(sealed);
}

async function writeFrame(framed, cipher, plaintext, maxFrameSize = MAX_FRAME_SIZE_V2) {
  const sealed = cipher.seal(plaintext);
  if (sealed.length > maxFrameSize) throw ErrFrameTooLarge;
  const frame = Buffer.concat([Buffer.alloc(LENGTH_PREFIX_SIZE), sealed]);
  frame.writeUInt32BE(sealed.length, 0);
  return framed.write(frame);
}

/**
 * Holds the shared password and KDF parameters for a V2 endpoint.
 */
export class V2 {
  /**
   * @param {string} password
   * @param {{ iterations?: number, maxFrameSize?: number }} [options]
   */
  constructor(password, options = {}) {
    if (!password) throw ErrWeakPassword;
    this.password = password;
    this.iterations = options.iterations && options.iterations > 0 ? options.iterations : DEFAULT_KDF_ITERATIONS;
    // Raise for beefier servers that transfer large documents; values below the
    // minimum valid frame size are ignored, keeping the default cap.
    this.maxFrameSize =
      options.maxFrameSize && options.maxFrameSize >= NONCE_SIZE + GCM_TAG_SIZE
        ? options.maxFrameSize
        : MAX_FRAME_SIZE_V2;
  }

  _cipherFromSalt(salt) {
    return new GCMCipher(deriveKey(this.password, salt, this.iterations));
  }

  /**
   * Server side of the handshake: send magic+version+salt, derive the cipher.
   * @param {FramedConn} framed
   * @returns {Promise<GCMCipher>}
   */
  async serverHandshake(framed) {
    const salt = crypto.randomBytes(SALT_SIZE);
    const header = Buffer.concat([Buffer.from(HANDSHAKE_MAGIC, 'ascii'), Buffer.from([PROTOCOL_VERSION_V2]), salt]);
    await framed.write(header);
    return this._cipherFromSalt(salt);
  }

  /**
   * Client side of the handshake: read and validate the header, derive cipher.
   * @param {FramedConn} framed
   * @returns {Promise<GCMCipher>}
   */
  async clientHandshake(framed) {
    let header;
    try {
      header = await framed.readExactly(HANDSHAKE_HEADER_SIZE);
    } catch {
      throw ErrHandshake;
    }
    if (header.subarray(0, HANDSHAKE_MAGIC.length).toString('ascii') !== HANDSHAKE_MAGIC) throw ErrHandshake;
    if (header[HANDSHAKE_MAGIC.length] !== PROTOCOL_VERSION_V2) throw ErrHandshake;
    const salt = header.subarray(HANDSHAKE_MAGIC.length + 1);
    return this._cipherFromSalt(salt);
  }
}

/**
 * Creates a V2 endpoint, throwing ErrWeakPassword on an empty password.
 * @param {string} password
 * @param {{ iterations?: number }} [options]
 * @returns {V2}
 */
export function NewV2(password, options) {
  return new V2(password, options);
}

/** Secure ATXP V2 client bound to a single connection. */
export class ClientV2 {
  /** Use {@link newClientV2} to construct (handshake is async). */
  constructor(framed, cipher, username, maxFrameSize = MAX_FRAME_SIZE_V2) {
    this.framed = framed;
    this.cipher = cipher;
    this.username = username;
    this.maxFrameSize = maxFrameSize;
    this.sendSeq = 0;
    this.recvSeq = 0;
  }

  async _send(type, data, filename) {
    this.sendSeq += 1;
    const msg = { type, data: Buffer.from(data), auth: { username: this.username }, filename };
    await writeFrame(this.framed, this.cipher, serializeV2(msg, this.sendSeq), this.maxFrameSize);
    const plaintext = await readFrame(this.framed, this.cipher, this.maxFrameSize);
    const { code, seq } = deserializeResponseV2(plaintext);
    if (seq <= this.recvSeq) throw ErrReplay;
    this.recvSeq = seq;
    return code;
  }

  /** @param {string} url @returns {Promise<number>} */
  sendURL(url) { return this._send(MT.URL, Buffer.from(url), ''); }
  /** @param {Buffer} doc @param {string} [filename] @returns {Promise<number>} */
  sendDocument(doc, filename) { return this._send(MT.DOCUMENT, doc, filename); }
  /** @param {string} message @returns {Promise<number>} */
  sendNotification(message) { return this._send(MT.NOTIFICATION, Buffer.from(message), ''); }
  /** @param {number} type @param {Buffer} data @param {string} [filename] @returns {Promise<number>} */
  send(type, data, filename) { return this._send(type, data, filename); }

  close() { this.framed.destroy(); }
}

/**
 * Connects a secure V2 client: performs the handshake and returns the client.
 * @param {net.Socket|tls.TLSSocket} socket
 * @param {string} password
 * @param {string} username
 * @param {{ iterations?: number }} [options]
 * @returns {Promise<ClientV2>}
 */
export async function newClientV2(socket, password, username, options) {
  const v = new V2(password, options);
  const framed = new FramedConn(socket);
  const cipher = await v.clientHandshake(framed);
  return new ClientV2(framed, cipher, username, v.maxFrameSize);
}

/**
 * Callback authorizing a connection by username only (V2 sends no password).
 * @callback AuthCallbackV2
 * @param {string} username
 * @returns {{ authorized: boolean, data: AuthData }}
 */

/** Secure ATXP V2 server. */
export class ServerV2 {
  /**
   * @param {string} password
   * @param {AuthCallbackV2} [authFn]
   * @param {{ iterations?: number }} [options]
   */
  constructor(password, authFn, options) {
    this.v = new V2(password, options);
    this.authFn = authFn;
    /** @type {Map<number, HandlerCallback>} */
    this.handlers = new Map();
    this.server = null;
  }

  /**
   * @param {number} type
   * @param {HandlerCallback} handler
   */
  registerHandler(type, handler) {
    this.handlers.set(type, handler);
  }

  /**
   * @param {number} port
   * @param {boolean} [isTls=false]
   * @param {tls.SecureContextOptions|null} [tlsOptions=null]
   * @returns {Promise<net.Server|tls.Server>}
   */
  listen(port, isTls = false, tlsOptions = null) {
    return new Promise((resolve, reject) => {
      const onConn = (conn) => this.handleConnection(conn);
      if (isTls) {
        if (!tlsOptions) return reject(new Error('tls configuration cannot be nil'));
        this.server = tls.createServer(tlsOptions, onConn);
      } else {
        this.server = net.createServer(onConn);
      }
      this.server.listen(port, () => resolve(this.server));
      this.server.on('error', reject);
    });
  }

  /** @param {net.Socket|tls.TLSSocket} socket */
  async handleConnection(socket) {
    const framed = new FramedConn(socket);
    let cipher;
    try {
      cipher = await this.v.serverHandshake(framed);
    } catch {
      framed.destroy();
      return;
    }

    const maxFrameSize = this.v.maxFrameSize;
    let recvSeq = 0;
    let sendSeq = 0;
    try {
      while (true) {
        let plaintext;
        try {
          plaintext = await readFrame(framed, cipher, maxFrameSize);
        } catch {
          break;
        }

        let parsed;
        try {
          parsed = deserializeV2(plaintext);
        } catch {
          sendSeq += 1;
          await writeFrame(framed, cipher, serializeResponseV2(ResponseCode.ERROR, sendSeq), maxFrameSize);
          break;
        }

        const { msg, seq } = parsed;
        if (seq <= recvSeq) {
          sendSeq += 1;
          await writeFrame(framed, cipher, serializeResponseV2(ResponseCode.ERROR, sendSeq), maxFrameSize);
          break;
        }
        recvSeq = seq;

        let authData = new AuthData(null);
        if (this.authFn) {
          const { authorized, data } = this.authFn(msg.auth.username);
          if (!authorized) {
            sendSeq += 1;
            await writeFrame(framed, cipher, serializeResponseV2(ResponseCode.UNAUTHORIZED, sendSeq), maxFrameSize);
            break;
          }
          authData = data;
        }

        const handler = this.handlers.get(msg.type);
        if (!handler) {
          sendSeq += 1;
          await writeFrame(framed, cipher, serializeResponseV2(ResponseCode.ERROR, sendSeq), maxFrameSize);
          continue;
        }

        const code = handler(msg, authData);
        sendSeq += 1;
        await writeFrame(framed, cipher, serializeResponseV2(code, sendSeq), maxFrameSize);
      }
    } finally {
      framed.destroy();
    }
  }

  close() {
    return new Promise((resolve) => {
      if (this.server) this.server.close(() => resolve());
      else resolve();
    });
  }
}
