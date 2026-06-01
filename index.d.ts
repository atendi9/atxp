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
   * Dispatches a dedicated Document binary buffer over the pipeline network connection.
   */
  sendDocument(documentBuffer: Buffer): Promise<ResponseCode>;

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