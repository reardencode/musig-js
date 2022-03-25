import createHash from 'create-hash';
import * as fc from 'fast-check';
import * as noble from '@noble/secp256k1';
import * as tiny from 'tiny-secp256k1';
import { AggregatePublicKey, MuSigFactory, MuSigPartialSig } from '..';
import * as baseCrypto from '../base_crypto';
import * as vectors from './vectors.json';

interface Signer {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  noncePair?: { secretNonce?: Uint8Array; publicNonce: Uint8Array };
  sig?: MuSigPartialSig;
}

noble.utils.sha256Sync = (...messages: Uint8Array[]): Uint8Array => {
  const sha256 = createHash('sha256');
  for (const message of messages) sha256.update(message);
  return sha256.digest();
};

const nobleCrypto = {
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
  sha256: noble.utils.sha256Sync!,
};

const tinyCrypto = {
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
  sha256: noble.utils.sha256Sync!,
};

const tweaks = new Array(5).fill(0).map(() => noble.utils.randomPrivateKey());
const tweaksXOnly = new Array(5).fill(0).map((_, i) => (tweaks[0][i] & 1) === 1);
const cryptos = [
  { cryptoName: 'noble', crypto: nobleCrypto },
  { cryptoName: 'tiny', crypto: tinyCrypto },
];

for (const { cryptoName, crypto } of cryptos) describe(cryptoName, function () {
  const musig = MuSigFactory(crypto);

  for (let nSigners = 1; nSigners < 5; nSigners++) describe(`random musig(${nSigners})`, function () {
    let publicKey: AggregatePublicKey;
    let signers: Signer[] = [];
    let message = noble.utils.randomBytes();
    let aggNonce: Uint8Array;
    let sig: Uint8Array;

    beforeAll(function () {
      for (let i = 0; i < nSigners; i++) {
        const secretKey = noble.utils.randomPrivateKey();
        const publicKey = noble.schnorr.getPublicKey(secretKey);
        signers.push({ secretKey, publicKey });
      }
    });

    it('aggregates keys', async function () {
      publicKey = await musig.keyAgg(signers.map(({ publicKey }) => publicKey));
    });

    for (let i = -1; i < tweaks.length; i++) {
      describe(`tweak(${i}) xOnly(${tweaksXOnly[i]})`, function () {
        if (i >= 0) {
          it('tweaks a key', function () {
            publicKey = musig.addTweaks(
              publicKey.session,
              tweaks.slice(i, i + 1),
              tweaksXOnly.slice(i, i + 1)
            );
          });

          it('aggregates keys with all tweaks', async function () {
            expect(
              await musig.keyAgg(
                signers.map(({ publicKey }) => publicKey),
                {
                  tweaks: tweaks.slice(0, i + 1),
                  tweaksXOnly: tweaksXOnly.slice(0, i + 1),
                }
              )
            ).toEqual(publicKey);
          });
        }

        it('makes nonces', async function () {
          for (let j = 0; j < signers.length; j++) {
            const signer = signers[j];
            switch (j) {
              case 1:
                const sessionId = new Uint8Array(32);
                sessionId[31] = nSigners;
                signer.noncePair = await musig.nonceGen({
                  sessionId,
                  secretKey: signer.secretKey,
                  message,
                  aggregatePublicKey: publicKey.publicKey,
                });
                break;
              case 2:
                signer.noncePair = await musig.nonceGen({
                  sessionId: noble.utils.randomBytes(),
                  secretKey: signer.secretKey,
                  message,
                  aggregatePublicKey: publicKey.publicKey,
                });
                break;
              case 3:
                signer.noncePair = await musig.nonceGen({
                  sessionId: noble.utils.randomBytes(),
                  secretKey: signer.secretKey,
                  message,
                  aggregatePublicKey: publicKey.publicKey,
                  extraInput: noble.utils.randomBytes(),
                });
                break;
              default:
                signer.noncePair = await musig.nonceGen({ sessionId: noble.utils.randomBytes() });
                break;
            }
          }
        });

        it('aggregates nonces', function () {
          aggNonce = musig.nonceAgg(signers.map(({ noncePair }) => noncePair!.publicNonce));
        });

        it('makes partial sigs', async function () {
          for (const signer of signers) {
            signer.sig = await musig.partialSign({
              message,
              secretKey: signer.secretKey,
              nonce: {
                secretNonce: signer.noncePair!.secretNonce!,
                publicNonce: signer.noncePair!.publicNonce,
              },
              aggNonce,
              session: publicKey.session
            });
            delete signer.noncePair!.secretNonce;
          }
        });

        it('verifies partial sigs', async function () {
          for (const signer of signers) {
            expect(
              await musig.partialVerify({
                sig: signer.sig!.sig,
                message,
                publicKey: signer.publicKey,
                publicNonce: signer.noncePair!.publicNonce,
                aggNonce,
                keyAggSession: publicKey.session
              })
            ).toBeTruthy();
          }
        });

        it('verifies partial sigs', async function () {
          for (const signer of signers) {
            expect(
              await musig.partialVerify({
                sig: signer.sig!.sig,
                message,
                publicKey: signer.publicKey,
                publicNonce: signer.noncePair!.publicNonce,
                aggNonce,
                keyAggSession: publicKey.session,
                session: signer.sig!.session
              })
            ).toBeTruthy();
          }
        });

        it('aggregates sigs', function () {
          sig = musig.signAgg(
            signers.map(({ sig }) => sig!.sig),
            signers[0].sig!.session
          );
        });

        it('verifies sig', async function () {
          expect(await noble.schnorr.verify(sig, message, publicKey.publicKey)).toBe(true);
        });
      });
    }
  });

  const basePublicKeys = vectors.publicKeys.map((pk) => Buffer.from(pk, 'hex'));

  describe('keyAgg vectors', function () {
    for (const [name, vector] of Object.entries(vectors.keyAggVectors)) {
      it(`aggregates keys ${name}`, async function () {
        const publicKeys = vector.publicKeyIndices.map((i) => basePublicKeys[i]);
        const key = await musig.keyAgg(publicKeys, { sort: false });
        expect(Buffer.from(key.publicKey).toString('hex')).toBe(vector.expected);
        const secondPublicKeyX = Buffer.from(key.session.rest.subarray(65, 97)).toString('hex');
        if ('secondPublicKeyIndex' in vector) {
          expect(secondPublicKeyX).toBe(publicKeys[vector.secondPublicKeyIndex].toString('hex'));
        } else {
          expect(secondPublicKeyX).toBe(new Buffer(32).toString('hex'));
        }
      });
    }
  });

  describe('nonceGen vectors', function () {
    const nonceArgs = {
      sessionId: Buffer.from(vectors.nonceArgs.sessionId, 'hex'),
      secretKey: Buffer.from(vectors.nonceArgs.secretKey, 'hex'),
      message: Buffer.from(vectors.nonceArgs.message, 'hex'),
      aggregatePublicKey: Buffer.from(vectors.nonceArgs.aggregatePublicKey, 'hex'),
      extraInput: Buffer.from(vectors.nonceArgs.extraInput, 'hex'),
    };
    for (const [name, vector] of Object.entries(vectors.nonceVectors)) {
      it(`generates nonces ${name}`, async function () {
        const args = { ...nonceArgs }
        vector.blankArgs.forEach((i) => (delete (args as Record<string, Uint8Array>)[i]));
        const nonce = await musig.nonceGen(args);
        expect(Buffer.from(nonce.secretNonce).toString('hex')).toBe(vector.expected);
      });
    }
  });

  describe('sign vectors', function () {
    for (const [name, vector] of Object.entries(vectors.signVectors)) {
      const { msg, secretNonce, aggNonce, signingKey, nonSignerKeyIndices } = vectors.signData;
      it(`partial signs ${name}`, async function () {
        const publicKeys: Uint8Array[] = nonSignerKeyIndices.map(
          (i) => basePublicKeys[i]
        );
        const signingPublicKey = noble.schnorr.getPublicKey(signingKey);
        publicKeys.splice(vector.signerIndex, 0, signingPublicKey);

        let parity, keyAggSession;
        if ('tweak' in vector) {
          ({ parity, session: keyAggSession } = await musig.keyAgg(publicKeys, {
            tweaks: [Buffer.from(vector.tweak, 'hex')],
            tweaksXOnly: [vector.xOnlyTweak],
            sort: false,
          }));
        } else {
          ({ parity, session: keyAggSession } = await musig.keyAgg(publicKeys, { sort: false }));
        }
        expect(parity).toBe(vector.expectedParity);

        const { sig, session } = await musig.partialSign({
          message: Buffer.from(msg, 'hex'),
          secretKey: Buffer.from(signingKey, 'hex'),
          nonce: { secretNonce: Buffer.from(secretNonce, 'hex') },
          aggNonce: Buffer.from(aggNonce, 'hex'),
          session: keyAggSession
        });
        expect(Buffer.from(sig).toString('hex')).toBe(vector.expectedS);
        expect(session[0]).toBe(vector.expectedNonceParity);
      });
    }
  });
});
