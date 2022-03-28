import createHash = require('create-hash');
import * as noble from '@noble/secp256k1';
import * as tiny from 'tiny-secp256k1';
import * as baseCrypto from '../base_crypto';

export const tinyCrypto = {
  ...baseCrypto,
  pointMultiply: tiny.pointMultiply,
  pointAdd: tiny.pointAdd,
  pointAddTweak: tiny.pointAddScalar,
  liftX: (p: Uint8Array): Uint8Array | null => {
    const pC = new Uint8Array(33);
    pC[0] = 2;
    pC.set(p, 1);
    return tiny.pointCompress(pC, false);
  },
  pointCompress: tiny.pointCompress,
  getPublicKey: tiny.pointFromScalar,
  taggedHash: noble.utils.taggedHashSync,
  sha256: (...messages: Uint8Array[]): Uint8Array => {
    const sha256 = createHash('sha256');
    for (const message of messages) sha256.update(message);
    return sha256.digest();
  },
};

noble.utils.sha256Sync = tinyCrypto.sha256;

export const nobleCrypto = {
  ...baseCrypto,
  pointMultiply: (p: Uint8Array, s: Uint8Array, compress: boolean): Uint8Array | null => {
    try {
      return noble.utils.pointMultiply(p, s, compress);
    } catch {
      return null;
    }
  },
  pointAdd: (a: Uint8Array, b: Uint8Array, compress: boolean): Uint8Array | null => {
    try {
      return noble.Point.fromHex(a).add(noble.Point.fromHex(b)).toRawBytes(compress);
    } catch {
      return null;
    }
  },
  pointAddTweak: (p: Uint8Array, t: Uint8Array, compress: boolean): Uint8Array | null => {
    try {
      return noble.utils.pointAddScalar(p, t, compress);
    } catch {
      return null;
    }
  },
  liftX: (p: Uint8Array): Uint8Array | null => {
    try {
      return noble.Point.fromHex(p).toRawBytes(false);
    } catch {
      return null;
    }
  },
  pointCompress: (p: Uint8Array, compress: boolean): Uint8Array => {
    return noble.Point.fromHex(p).toRawBytes(compress);
  },
  getPublicKey: (s: Uint8Array, compress: boolean): Uint8Array | null => {
    try {
      return noble.getPublicKey(s, compress);
    } catch {
      return null;
    }
  },
  taggedHash: noble.utils.taggedHashSync,
  sha256: tinyCrypto.sha256,
};
