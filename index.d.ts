/// <reference types="node" />

import { Socket } from 'node:net';
import { TLSSocket, SecureContextOptions } from 'node:tls';
import { Server as NetServer } from 'node:net';
import { Server as TlsServer } from 'node:tls';

/**
 * Message Type (MT) enumeration for ATXP frames.
 */
export declare enum MT {
  URL = 0,
  DOCUMENT = 1,
  NOTIFICATION = 2
}

/**
 * Response Code enumeration sent by ATXP servers.
 */
export declare enum ResponseCode {
  OK = 0,
  ERROR = 1,
  UNAUTHORIZED = 2
}

/**
 * Error thrown when an invalid or malformed ATXP packet is processed.
 */
export declare const ErrInvalidFormat: Error;

/**
 * Class representing optional authentication metadata, mimicking box.Optional behavior.
 */
export declare class AuthData {
  constructor(value?: Record<string, any> | null);
  protected value: Record<string, any> | null;
  isEmpty(): boolean;
  get(): Record<string, any> | null;
}

/**
 * Authentication structure containing credentials.
 */
export interface MessageAuth {
  username?: string;
  password?: string;
}

/**
 * Structured ATXP message frame representation.
 */
export interface AtxpMessage {
  type: MT;
  data: Buffer;
  auth: MessageAuth;
  filename?: string;
}

/**
 * Structured response payload object returned by authentication check routines.
 */
export interface AuthResult {
  authorized: boolean;
  data: AuthData;
}

/**
 * Callback definition for processing ATXP authentication checks.
 */
export type AuthCallback = (username: string, password: string) => AuthResult;

/**
 * Callback definition for processing custom operational business logic message updates.
 */
export type HandlerCallback = (msg: AtxpMessage, authData: AuthData) => ResponseCode;

/**
 * Converts a numeric Message Type (MT) enum to its equivalent string representation.
 */
export function typeToString(messageType: MT): 'URL' | 'Document' | 'Notification' | 'UNKNOWN';

/**
 * Converts a valid ATXP message type string back into its numeric enum equivalent.
 */
export function stringToType(str: string): MT | -1;

/**
 * Serializes a structured message object into a single raw Buffer matching the ATXP specification.
 */
export function serialize(msg: AtxpMessage): Buffer;

/**
 * Deserializes a raw string frame buffer back into a structured ATXP message entity.
 */
export function deserialize(bufferStr: string): AtxpMessage;

/**
 * Reads data segments asynchronously from a connection stream until it identifies the ATXP closing payload delimiter.
 */
export function receive(conn: Socket | TLSSocket): Promise<string>;

/**
 * Formats, packs, and writes an ATXP protocol message structure payload directly down a network link.
 */
export function send(conn: Socket | TLSSocket, msg: AtxpMessage): Promise<number>;

/**
 * Transmits an isolated ATXP standard code response back across the client node stream.
 */
export function sendResponse(conn: Socket | TLSSocket, responseCode: ResponseCode): Promise<number>;

/**
 * Blocks and handles ingestion parameters asynchronously awaiting a structured ATXP protocol status response code.
 */
export function receiveResponse(conn: Socket | TLSSocket): Promise<ResponseCode>;

/**
 * Class representing an ATXP protocol Client interface.
 */
export class Client {
  /**
   * Create an ATXP Client.
   */
  constructor(conn: Socket | TLSSocket, username: string, password: string);

  protected conn: Socket | TLSSocket;
  protected auth: MessageAuth;

  /**
   * Dispatches a structured URL transmission frame over the pipeline wire connection.
   */
  sendURL(url: string): Promise<ResponseCode>;

  /**
   * Dispatches a dedicated Document binary buffer over the pipeline network connection with optional filename tracking.
   */
  sendDocument(documentBuffer: Buffer, filename?: string): Promise<ResponseCode>;

  /**
   * Dispatches a structured text notification notification string component frame across the wire channel.
   */
  sendNotification(message: string): Promise<ResponseCode>;
}

/**
 * Class representing an ATXP protocol server layer engine daemon.
 */
export class Server {
  /**
   * Create an ATXP Server.
   */
  constructor(authFn?: AuthCallback);

  protected handlers: Map<MT, HandlerCallback>;
  protected authFn?: AuthCallback;
  protected server: NetServer | TlsServer | null;

  /**
   * Registers a callback mapping function handler to manage execution flows whenever a specified message type lands.
   */
  registerHandler(messageType: MT, handler: HandlerCallback): void;

  /**
   * Initialises the listener networking server configuration hooks across targeted processing socket boundaries.
   */
  listen(port: number, isTls?: boolean, tlsOptions?: SecureContextOptions | null): Promise<NetServer | TlsServer>;

  /**
   * Asynchronously polls network socket pipes, validating connection flows, authenticating clients, and routing requests safely.
   */
  handleConnection(conn: Socket | TLSSocket): Promise<void>;

  /**
   * Dismantles ongoing binding hooks cleanly shutting down network processes.
   */
  close(): Promise<void>;
}

/**
 * Factory creating validation handlers dedicated to testing structural accuracy on incoming URL payloads.
 */
export function validateURLHandler(): HandlerCallback;

/**
 * Factory creating validation handlers checking capacity limitations on incoming Document data frames.
 */
export function validateDocumentHandler(maxBytes: number): HandlerCallback;

// =====================================================================
// ATXP V2 — secure layer (password-derived encryption, binary-safe framing)
// =====================================================================

/** Sizing constants for the V2 secure layer. */
export const SALT_SIZE: number;
export const NONCE_SIZE: number;
export const KEY_SIZE: number;
export const GCM_TAG_SIZE: number;
export const LENGTH_PREFIX_SIZE: number;
export const DEFAULT_KDF_ITERATIONS: number;
export const MAX_FRAME_SIZE_V2: number;
export const PROTOCOL_VERSION_V2: number;
export const HANDSHAKE_MAGIC: string;
export const DEFAULT_IO_TIMEOUT_MS: number;

/** Sentinel errors for the V2 layer. */
export const ErrInvalidChecksum: Error;
export const ErrFrameTooLarge: Error;
export const ErrFrameTooSmall: Error;
export const ErrHandshake: Error;
export const ErrWeakPassword: Error;
export const ErrReplay: Error;
export const ErrInvalidEnvelope: Error;

/** A registrable V2 message type. */
export interface MT_V2 {
  name: string;
  code: number;
  description: string;
}

/** Registers a new V2 message type; returns false if the code is already used. */
export function newMT(mt: MT_V2): boolean;
/** Looks up a registered message type by code. */
export function lookupMT(code: number): MT_V2 | undefined;
/** Resolves a message type code to its name, or 'UNKNOWN'. */
export function typeToStringV2(code: number): string;
/** Resolves a message type name to its code, or -1 when unknown. */
export function stringToTypeV2(name: string): number;

/** Options for V2 endpoints. */
export interface V2Options {
  /** PBKDF2 iteration count. Both peers must agree. Default 600000. */
  iterations?: number;
  /**
   * Maximum encrypted frame size in bytes. Raise for servers transferring large
   * documents. Values below the minimum valid frame size are ignored. Default
   * 16 MiB (MAX_FRAME_SIZE_V2).
   */
  maxFrameSize?: number;
}

/** Derives a 32-byte AES-256 key from a password and salt via PBKDF2-HMAC-SHA256. */
export function deriveKey(password: string, salt: Buffer, iterations: number): Buffer;

/** AES-256-GCM cipher producing the layout nonce || ciphertext || tag. */
export class GCMCipher {
  constructor(key: Buffer);
  seal(plaintext: Buffer): Buffer;
  open(frame: Buffer): Buffer;
}

/** Encodes a message and sequence number into the V2 inner plaintext envelope. */
export function serializeV2(msg: AtxpMessage, seq: number): Buffer;
/** Decodes a V2 message envelope. */
export function deserializeV2(plaintext: Buffer): { seq: number; msg: AtxpMessage };

/** Holds the shared password and KDF parameters for a V2 endpoint. */
export class V2 {
  constructor(password: string, options?: V2Options);
  serverHandshake(framed: unknown): Promise<GCMCipher>;
  clientHandshake(framed: unknown): Promise<GCMCipher>;
}

/** Creates a V2 endpoint, throwing ErrWeakPassword on an empty password. */
export function NewV2(password: string, options?: V2Options): V2;

/** Callback authorizing a connection by username only (V2 sends no password). */
export type AuthCallbackV2 = (username: string) => AuthResult;

/** Secure ATXP V2 client bound to a single connection. */
export class ClientV2 {
  sendURL(url: string): Promise<ResponseCode>;
  sendDocument(doc: Buffer, filename?: string): Promise<ResponseCode>;
  sendNotification(message: string): Promise<ResponseCode>;
  send(type: number, data: Buffer, filename?: string): Promise<ResponseCode>;
  close(): void;
}

/** Connects a secure V2 client: performs the handshake and returns the client. */
export function newClientV2(
  socket: Socket | TLSSocket,
  password: string,
  username: string,
  options?: V2Options
): Promise<ClientV2>;

/** Secure ATXP V2 server. */
export class ServerV2 {
  constructor(password: string, authFn?: AuthCallbackV2, options?: V2Options);
  registerHandler(type: number, handler: HandlerCallback): void;
  listen(port: number, isTls?: boolean, tlsOptions?: SecureContextOptions | null): Promise<NetServer | TlsServer>;
  handleConnection(socket: Socket | TLSSocket): Promise<void>;
  close(): Promise<void>;
}
