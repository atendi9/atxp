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

  test('should throw error on deserialize when packet is malformed', () => {
    assert.throws(() => {
      deserialize('INVALID_PACKET_WITHOUT_DELIMITERS');
    }, ErrInvalidFormat);
  });

  test('validateURLHandler should validate HTTP and HTTPS prefixes correctly', () => {
    const handler = validateURLHandler();

    const validMsg = { data: Buffer.from('https://atendi9.com') };
    const invalidMsg = { data: Buffer.from('ftp://atendi9.com') };
    const emptyMsg = { data: Buffer.alloc(0) };

    assert.strictEqual(handler(validMsg), ResponseCode.OK);
    assert.strictEqual(handler(invalidMsg), ResponseCode.ERROR);
    assert.strictEqual(handler(emptyMsg), ResponseCode.ERROR);
  });

  test('validateDocumentHandler should check bounds and constraint sizes', () => {
    const handler = validateDocumentHandler(10);

    const exactBoundMsg = { data: Buffer.alloc(10) };
    const overflowMsg = { data: Buffer.alloc(11) };

    assert.strictEqual(handler(exactBoundMsg), ResponseCode.OK);
    assert.strictEqual(handler(overflowMsg), ResponseCode.ERROR);
  });
});

describe('ATXP Integration Network Tests', () => {
  let server;
  let port = 9999;

  before(async () => {
    const authVerifier = (user, pass) => user === 'user123' && pass === 'pass123';
    server = new Server(authVerifier);
    
    server.registerHandler(MT.URL, validateURLHandler());
    server.registerHandler(MT.NOTIFICATION, (msg) => ResponseCode.OK);

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