import { test, describe, before, after } from 'node:test';
import assert from 'node:assert';
import net from 'node:net';
import { 
  MT, 
  ResponseCode, 
  serialize, 
  deserialize, 
  Server, 
  Client, 
  AuthData,
  validateURLHandler, 
  validateDocumentHandler,
  ErrInvalidFormat
} from './atxp.js';

describe('ATXP Protocol Unit Tests', () => {

  test('should correctly serialize and deserialize a valid message frame', () => {
    const originalMsg = {
      type: MT.URL,
      data: Buffer.from('https://atendi9.com'),
      auth: { username: 'admin', password: 'secretpassword' }
    };

    const payload = serialize(originalMsg);
    assert.ok(payload.length > 0);

    const deserializedMsg = deserialize(payload.toString('utf8'));

    assert.strictEqual(deserializedMsg.type, originalMsg.type);
    assert.strictEqual(deserializedMsg.data.toString(), originalMsg.data.toString());
    assert.strictEqual(deserializedMsg.auth.username, originalMsg.auth.username);
    assert.strictEqual(deserializedMsg.auth.password, originalMsg.auth.password);
  });

  test('should correctly serialize and deserialize a Document with filename', () => {
    const originalMsg = {
      type: MT.DOCUMENT,
      data: Buffer.from('filecontentbytes'),
      auth: { username: 'admin', password: 'password' },
      filename: 'invoice.pdf'
    };

    const payload = serialize(originalMsg);
    const deserializedMsg = deserialize(payload.toString('utf8'));

    assert.strictEqual(deserializedMsg.type, MT.DOCUMENT);
    assert.strictEqual(deserializedMsg.filename, 'invoice.pdf');
  });

  test('should throw error on deserialize when packet is malformed', () => {
    assert.throws(() => {
      deserialize('INVALID_PACKET_WITHOUT_DELIMITERS');
    }, ErrInvalidFormat);
  });

  test('AuthData should handle empty and valid state values correctly', () => {
    const emptyAuth = new AuthData(null);
    assert.strictEqual(emptyAuth.isEmpty(), true);
    assert.strictEqual(emptyAuth.get(), null);

    const metadata = { userId: '12345', role: 'admin' };
    const filledAuth = new AuthData(metadata);
    assert.strictEqual(filledAuth.isEmpty(), false);
    assert.deepEqual(filledAuth.get(), metadata);
  });

  test('validateURLHandler should validate HTTP and HTTPS prefixes correctly with AuthData injected', () => {
    const handler = validateURLHandler();
    const dummyAuth = new AuthData(null);

    const validMsg = { data: Buffer.from('https://atendi9.com') };
    const invalidMsg = { data: Buffer.from('ftp://atendi9.com') };
    const emptyMsg = { data: Buffer.alloc(0) };

    assert.strictEqual(handler(validMsg, dummyAuth), ResponseCode.OK);
    assert.strictEqual(handler(invalidMsg, dummyAuth), ResponseCode.ERROR);
    assert.strictEqual(handler(emptyMsg, dummyAuth), ResponseCode.ERROR);
  });

  test('validateDocumentHandler should check bounds and constraint sizes with AuthData injected', () => {
    const handler = validateDocumentHandler(10);
    const dummyAuth = new AuthData(null);

    const exactBoundMsg = { data: Buffer.alloc(10) };
    const overflowMsg = { data: Buffer.alloc(11) };

    assert.strictEqual(handler(exactBoundMsg, dummyAuth), ResponseCode.OK);
    assert.strictEqual(handler(overflowMsg, dummyAuth), ResponseCode.ERROR);
  });
});

describe('ATXP Integration Network Tests', () => {
  let server;
  let port = 9999;
  let lastSessionRole = '';

  before(async () => {
    const authVerifier = (user, pass) => {
      if (user === 'user123' && pass === 'pass123') {
        return {
          authorized: true,
          data: new AuthData({ role: 'operator', internallyVerified: true })
        };
      }
      return {
        authorized: false,
        data: new AuthData(null)
      };
    };

    server = new Server(authVerifier);
    
    server.registerHandler(MT.URL, validateURLHandler());
    
    server.registerHandler(MT.NOTIFICATION, (msg, authData) => {
      if (!authData.isEmpty()) {
        const info = authData.get();
        lastSessionRole = info?.role || '';
      }
      return ResponseCode.OK;
    });

    await server.listen(port);
  });

  after(async () => {
    await server.close();
  });

  test('Client should connect, authenticate, and receive ResponseCode.OK on valid request', () => {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ port }, async () => {
        try {
          const client = new Client(socket, 'user123', 'pass123');
          const response = await client.sendURL('https://atendi9.com');
          
          assert.strictEqual(response, ResponseCode.OK);
          socket.destroy();
          resolve();
        } catch (err) {
          socket.destroy();
          reject(err);
        }
      });
    });
  });

  test('Server handler should successfully access data injected through AuthData flow', () => {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ port }, async () => {
        try {
          const client = new Client(socket, 'user123', 'pass123');
          const response = await client.sendNotification('Testing session storage data');
          
          assert.strictEqual(response, ResponseCode.OK);
          assert.strictEqual(lastSessionRole, 'operator');
          socket.destroy();
          resolve();
        } catch (err) {
          socket.destroy();
          reject(err);
        }
      });
    });
  });

  test('Client should receive ResponseCode.UNAUTHORIZED with invalid credentials', () => {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ port }, async () => {
        try {
          const client = new Client(socket, 'wrong_user', 'wrong_pass');
          const response = await client.sendNotification('Hello World');
          
          assert.strictEqual(response, ResponseCode.UNAUTHORIZED);
          socket.destroy();
          resolve();
        } catch (err) {
          socket.destroy();
          reject(err);
        }
      });
    });
  });
});

import crypto from 'node:crypto';
import {
  newMT,
  lookupMT,
  typeToStringV2,
  stringToTypeV2,
  deriveKey,
  GCMCipher,
  serializeV2,
  deserializeV2,
  NewV2,
  ServerV2,
  newClientV2,
  SALT_SIZE,
  NONCE_SIZE,
  KEY_SIZE,
  ErrInvalidChecksum,
  ErrWeakPassword,
  ErrInvalidEnvelope,
} from './atxp.js';

// Cross-language known-answer vectors — identical to the Go suite
// (crypto_v2_test.go), proving byte-identical PBKDF2 and AES-256-GCM.
const KAT_PBKDF2 = 'c30e125ad616b2f56073aca70bf0c0009177eca5e2553263a1c8de8e1c63d684';
const KAT_GCM = '66a2b1399775301e0dd42545400842bddb19187c';

const TRICKY = Buffer.from('URL\t\tx\t\tAuth:user::pass\n\n\x00 %PDF-1.7 \xff\xfe', 'binary');

describe('ATXP V2 — crypto parity', () => {
  test('PBKDF2 known-answer matches Go', () => {
    const key = deriveKey('pw', Buffer.alloc(SALT_SIZE, 0x00), 1);
    assert.strictEqual(key.length, KEY_SIZE);
    assert.strictEqual(key.toString('hex'), KAT_PBKDF2);
  });

  test('AES-256-GCM known-answer matches Go', () => {
    const key = Buffer.alloc(KEY_SIZE, 0x01);
    const nonce = Buffer.alloc(NONCE_SIZE, 0x02);
    const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
    const ct = Buffer.concat([c.update(Buffer.from('atxp')), c.final()]);
    assert.strictEqual(Buffer.concat([ct, c.getAuthTag()]).toString('hex'), KAT_GCM);
  });

  test('GCMCipher round trip preserves binary payloads', () => {
    const cipher = new GCMCipher(deriveKey('pw', Buffer.alloc(SALT_SIZE, 0x03), 1));
    const sealed = cipher.seal(TRICKY);
    assert.ok(sealed.length >= NONCE_SIZE + 16);
    assert.deepStrictEqual(cipher.open(sealed), TRICKY);
  });

  test('GCMCipher rejects wrong password and tampering', () => {
    const salt = Buffer.alloc(SALT_SIZE, 0x04);
    const good = new GCMCipher(deriveKey('right', salt, 1));
    const bad = new GCMCipher(deriveKey('wrong', salt, 1));
    const sealed = good.seal(Buffer.from('secret'));
    assert.throws(() => bad.open(sealed), ErrInvalidChecksum);

    const tampered = Buffer.from(sealed);
    tampered[tampered.length - 1] ^= 0xff;
    assert.throws(() => good.open(tampered), ErrInvalidChecksum);
  });
});

describe('ATXP V2 — message type registry', () => {
  test('builtin types resolve', () => {
    assert.strictEqual(typeToStringV2(MT.URL), 'URL');
    assert.strictEqual(typeToStringV2(MT.DOCUMENT), 'DOCUMENT');
    assert.strictEqual(typeToStringV2(999999), 'UNKNOWN');
    assert.strictEqual(stringToTypeV2('URL'), MT.URL);
    assert.strictEqual(stringToTypeV2('NOPE'), -1);
  });

  test('newMT registers and rejects duplicates', () => {
    assert.strictEqual(newMT({ name: 'WEBHOOK', code: 4242, description: 'webhook' }), true);
    assert.strictEqual(newMT({ name: 'DUP', code: 4242, description: 'dup' }), false);
    assert.strictEqual(lookupMT(4242).name, 'WEBHOOK');
    assert.strictEqual(newMT({ name: 'X', code: MT.URL, description: 'override' }), false);
  });
});

describe('ATXP V2 — envelope', () => {
  test('round trip with tricky binary payload', () => {
    const msg = { type: MT.DOCUMENT, data: TRICKY, auth: { username: 'gopher' }, filename: 'a::b\t.pdf' };
    const { seq, msg: out } = deserializeV2(serializeV2(msg, 42));
    assert.strictEqual(seq, 42);
    assert.strictEqual(out.type, MT.DOCUMENT);
    assert.strictEqual(out.auth.username, 'gopher');
    assert.strictEqual(out.filename, 'a::b\t.pdf');
    assert.deepStrictEqual(out.data, TRICKY);
  });

  test('rejects malformed envelopes', () => {
    assert.throws(() => deserializeV2(Buffer.from([0x02])), ErrInvalidEnvelope); // wrong kind
    assert.throws(() => deserializeV2(Buffer.from([0x01])), ErrInvalidEnvelope); // missing seq
  });
});

describe('ATXP V2 — secure integration', () => {
  test('NewV2 rejects empty password', () => {
    assert.throws(() => NewV2(''), ErrWeakPassword);
  });

  async function withServer(password, authFn, register, fn) {
    const server = new ServerV2(password, authFn, { iterations: 1 });
    register(server);
    const listening = await server.listen(0);
    const { port } = listening.address();
    try {
      await fn(port);
    } finally {
      await server.close();
    }
  }

  function connect(port, password, username) {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ port }, async () => {
        try {
          resolve(await newClientV2(socket, password, username, { iterations: 1 }));
        } catch (err) {
          reject(err);
        }
      });
      socket.on('error', reject);
    });
  }

  test('binary document round-trips encrypted end to end', async () => {
    let received = null;
    let receivedName = null;
    await withServer('shared', null, (s) => {
      s.registerHandler(MT.DOCUMENT, (msg) => {
        received = msg.data;
        receivedName = msg.filename;
        return ResponseCode.OK;
      });
    }, async (port) => {
      const client = await connect(port, 'shared', 'uploader');
      const pdf = Buffer.concat([Buffer.from('%PDF-1.7\n'), TRICKY]);
      const code = await client.sendDocument(pdf, 'report.pdf');
      assert.strictEqual(code, ResponseCode.OK);
      assert.deepStrictEqual(received, pdf);
      assert.strictEqual(receivedName, 'report.pdf');
      client.close();
    });
  });

  test('custom message type and multiple frames over one connection', async () => {
    newMT({ name: 'EVENT', code: 5000, description: 'event' });
    await withServer('pw', null, (s) => {
      s.registerHandler(MT.URL, validateURLHandler());
      s.registerHandler(5000, () => ResponseCode.OK);
    }, async (port) => {
      const client = await connect(port, 'pw', 'u');
      assert.strictEqual(await client.sendURL('https://atendi9.com'), ResponseCode.OK);
      assert.strictEqual(await client.send(5000, Buffer.from('{"e":1}'), ''), ResponseCode.OK);
      client.close();
    });
  });

  test('unauthorized username is rejected', async () => {
    const authFn = (username) => ({ authorized: username === 'trusted', data: new AuthData(null) });
    await withServer('pw', authFn, (s) => {
      s.registerHandler(MT.NOTIFICATION, () => ResponseCode.OK);
    }, async (port) => {
      const client = await connect(port, 'pw', 'intruder');
      assert.strictEqual(await client.sendNotification('hi'), ResponseCode.UNAUTHORIZED);
      client.close();
    });
  });

  test('unknown message type returns ERROR but keeps connection alive', async () => {
    await withServer('pw', null, (s) => {
      s.registerHandler(MT.URL, validateURLHandler());
    }, async (port) => {
      const client = await connect(port, 'pw', 'u');
      assert.strictEqual(await client.sendNotification('unhandled'), ResponseCode.ERROR);
      assert.strictEqual(await client.sendURL('https://atendi9.com'), ResponseCode.OK);
      client.close();
    });
  });

  test('wrong password cannot communicate', async () => {
    await withServer('correct', null, (s) => {
      s.registerHandler(MT.URL, validateURLHandler());
    }, async (port) => {
      const client = await connect(port, 'wrong', 'u');
      await assert.rejects(client.sendURL('https://atendi9.com'));
      client.close();
    });
  });

  test('configurable frame cap allows larger documents', async () => {
    const bigSize = (1 << 24) + 1024; // just above the default 16 MiB cap
    let receivedLen = 0;
    const server = new ServerV2('pw', null, { iterations: 1, maxFrameSize: 64 << 20 });
    server.registerHandler(MT.DOCUMENT, (msg) => {
      receivedLen = msg.data.length;
      return ResponseCode.OK;
    });
    const listening = await server.listen(0);
    const { port } = listening.address();
    try {
      const socket = net.createConnection({ port });
      const client = await newClientV2(socket, 'pw', 'u', { iterations: 1, maxFrameSize: 64 << 20 });
      const code = await client.sendDocument(Buffer.alloc(bigSize, 0x7a), 'big.bin');
      assert.strictEqual(code, ResponseCode.OK);
      assert.strictEqual(receivedLen, bigSize);
      client.close();
    } finally {
      await server.close();
    }
  });

  test('default cap rejects an oversized document', async () => {
    const bigSize = (1 << 24) + 1; // just above the default cap
    const server = new ServerV2('pw', null, { iterations: 1 });
    server.registerHandler(MT.DOCUMENT, () => ResponseCode.OK);
    const listening = await server.listen(0);
    const { port } = listening.address();
    try {
      const socket = net.createConnection({ port });
      const client = await newClientV2(socket, 'pw', 'u', { iterations: 1 });
      await assert.rejects(client.sendDocument(Buffer.alloc(bigSize, 0x7a), 'big.bin'));
      client.close();
    } finally {
      await server.close();
    }
  });
});
