import net from 'node:net';
import tls from 'node:tls';

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

  const part1 = Buffer.from(`${typeStr}\t\t`);
  const part2 = Buffer.from(`\t\tAuth:${username}::${password}\n\n`);

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
  const delimiterIdx = authStr.indexOf('::');
  if (delimiterIdx === -1) {
    throw ErrInvalidFormat;
  }

  const username = authStr.substring(0, delimiterIdx);
  const password = authStr.substring(delimiterIdx + 2);

  return {
    type: stringToType(typeStr),
    data: Buffer.from(dataStr),
    auth: { username, password }
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
   * Dispatches a dedicated Document binary buffer over the pipeline network connection.
   * @param {Buffer} documentBuffer - The document content payload package.
   * @returns {Promise<number>} Resolves to the specific response verification code returned by the server.
   */
  async sendDocument(documentBuffer) {
    const msg = {
      type: MT.DOCUMENT,
      data: documentBuffer,
      auth: this.auth
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
 * Callback definition for processing ATXP authentication checks.
 * @callback AuthCallback
 * @param {string} username - Extracted user security profile validation identity.
 * @param {string} password - Extracted user pairing authentication token verify keys.
 * @returns {boolean} True if validation matches, false if access authentication credentials fail validation.
 */

/**
 * Callback definition for processing custom operational business logic message updates.
 * @callback HandlerCallback
 * @param {AtxpMessage} msg - The fully deserialized message structure.
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

        if (this.authFn && !this.authFn(msg.auth.username, msg.auth.password)) {
          await sendResponse(conn, ResponseCode.UNAUTHORIZED);
          break;
        }

        const handler = this.handlers.get(msg.type);
        if (!handler) {
          await sendResponse(conn, ResponseCode.ERROR);
          continue;
        }

        const code = handler(msg);
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
  return (msg) => {
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
  return (msg) => {
    if (!msg.data || msg.data.length === 0 || msg.data.length > maxBytes) {
      return ResponseCode.ERROR;
    }
    return ResponseCode.OK;
  };
}