import * as noble from '@noble/secp256k1';
import { AggregatePublicKey, MuSigFactory, MuSigPartialSig } from '../index';
import { nobleCrypto, tinyCrypto } from './utils';
import * as vectors from './musig_vectors.json';

interface Signer {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  noncePair?: { secretNonce?: Uint8Array; publicNonce: Uint8Array };
  sig?: Uint8Array;
}

const validX = noble.schnorr.getPublicKey(noble.utils.randomPrivateKey());
const invalidX = Buffer.from(
  'a02b2026e3b9c3842684d892cd8cf3a30530c21ec6d75d1d03ed9f4f536af692',
  'hex'
);
const invalidPoint = Buffer.from(
  '0400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001',
  'hex'
);
const notSecret = Buffer.from(
  'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'hex'
);
const validTweak = noble.utils.randomPrivateKey();

const nonceArgs = {
  sessionId: Buffer.from(vectors.nonceArgs.sessionId, 'hex'),
  secretKey: Buffer.from(vectors.nonceArgs.secretKey, 'hex'),
  msg: Buffer.from(vectors.nonceArgs.msg, 'hex'),
  aggregatePublicKey: Buffer.from(vectors.nonceArgs.aggregatePublicKey, 'hex'),
  extraInput: Buffer.from(vectors.nonceArgs.extraInput, 'hex'),
};

const tweaks = new Array(5).fill(0).map(() => noble.utils.randomPrivateKey());
const tweaksXOnly = new Array(5).fill(0).map((_, i) => (tweaks[0][i] & 1) === 1);
const cryptos = [
  { cryptoName: 'noble', crypto: nobleCrypto },
  { cryptoName: 'tiny', crypto: tinyCrypto },
];

for (const { cryptoName, crypto } of cryptos) {
  describe(cryptoName, function () {
    const musig = MuSigFactory(crypto);

    for (let nSigners = 1; nSigners < 5; nSigners++)
      describe(`random musig(${nSigners})`, function () {
        let aggregatePublicKey: AggregatePublicKey;
        let signers: Signer[] = [];
        let msg = noble.utils.randomBytes();
        let aggNonce: Uint8Array;
        let signingSession: Uint8Array;
        let sig: Uint8Array;

        beforeAll(function () {
          for (let i = 0; i < nSigners; i++) {
            const secretKey = noble.utils.randomPrivateKey();
            const publicKey = noble.schnorr.getPublicKey(secretKey);
            signers.push({ secretKey, publicKey });
          }
        });

        it('aggregates keys', function () {
          aggregatePublicKey = musig.keyAgg(signers.map(({ publicKey }) => publicKey));
        });

        for (let i = -1; i < tweaks.length; i++) {
          describe(`tweak(${i}) xOnly(${tweaksXOnly[i]})`, function () {
            if (i >= 0) {
              it('tweaks a key', function () {
                aggregatePublicKey = musig.addTweaks(
                  aggregatePublicKey.keyAggSession,
                  tweaks.slice(i, i + 1),
                  tweaksXOnly.slice(i, i + 1)
                );
              });

              it('aggregates keys with all tweaks', function () {
                expect(
                  musig.keyAgg(
                    signers.map(({ publicKey }) => publicKey),
                    {
                      tweaks: tweaks.slice(0, i + 1),
                      tweaksXOnly: tweaksXOnly.slice(0, i + 1),
                    }
                  )
                ).toEqual(aggregatePublicKey);
              });
            }

            it('makes nonces', function () {
              for (let j = 0; j < signers.length; j++) {
                const signer = signers[j];
                switch (j) {
                  case 1:
                    const sessionId = new Uint8Array(32);
                    sessionId[31] = nSigners;
                    signer.noncePair = musig.nonceGen({
                      sessionId,
                      secretKey: signer.secretKey,
                      msg,
                      aggregatePublicKey: aggregatePublicKey.publicKey,
                    });
                    break;
                  case 2:
                    signer.noncePair = musig.nonceGen({
                      sessionId: noble.utils.randomBytes(),
                      secretKey: signer.secretKey,
                      msg,
                      aggregatePublicKey: aggregatePublicKey.publicKey,
                    });
                    break;
                  case 3:
                    signer.noncePair = musig.nonceGen({
                      sessionId: noble.utils.randomBytes(),
                      secretKey: signer.secretKey,
                      msg,
                      aggregatePublicKey: aggregatePublicKey.publicKey,
                      extraInput: noble.utils.randomBytes(),
                    });
                    break;
                  default:
                    signer.noncePair = musig.nonceGen({
                      sessionId: noble.utils.randomBytes(),
                    });
                    break;
                }
              }
            });

            it('aggregates nonces', function () {
              aggNonce = musig.nonceAgg(signers.map(({ noncePair }) => noncePair!.publicNonce));
            });

            it('creates a signing sesion', function () {
              signingSession = musig.createSigningSession(
                aggNonce,
                msg,
                aggregatePublicKey.keyAggSession
              );
              expect(signingSession).toHaveLength(161);
            });

            it(`makes partial sigs ${signers.length % 2 === 1 ? 'w/session' : ''}`, function () {
              for (const signer of signers) {
                const { sig, signingSession: sigSigningSession } = musig.partialSign({
                  msg,
                  secretKey: signer.secretKey,
                  nonce: {
                    secretNonce: signer.noncePair!.secretNonce!,
                    publicNonce: signer.noncePair!.publicNonce,
                  },
                  aggNonce,
                  keyAggSession: aggregatePublicKey.keyAggSession,
                  signingSession: signers.length % 2 === 1 ? signingSession : undefined,
                });
                signer.sig = sig;
                expect(Buffer.from(sigSigningSession)).toEqual(Buffer.from(signingSession));
                delete signer.noncePair!.secretNonce;
              }
            });

            it(`verifies partial sigs ${signers.length % 2 === 1 ? 'w/session' : ''}`, function () {
              for (const signer of signers) {
                const result = musig.partialVerify({
                  sig: signer.sig!,
                  msg,
                  publicKey: signer.publicKey,
                  publicNonce: signer.noncePair!.publicNonce,
                  aggNonce,
                  keyAggSession: aggregatePublicKey.keyAggSession,
                  signingSession: signers.length % 2 === 1 ? signingSession : undefined,
                });
                if (!result) throw new Error('Expected result to be truthy');
                expect(Buffer.from(result.signingSession)).toEqual(Buffer.from(signingSession));
              }
            });

            it('aggregates sigs', function () {
              sig = musig.signAgg(
                signers.map(({ sig }) => sig!),
                signingSession
              );
            });

            it('verifies sig', function () {
              expect(noble.schnorr.verifySync(sig, msg, aggregatePublicKey.publicKey)).toBe(true);
            });
          });
        }
      });

    const basePublicKeys = vectors.publicKeys.map((pk) => Buffer.from(pk, 'hex'));

    describe('keyAgg vectors', function () {
      for (const [name, vector] of Object.entries(vectors.keyAggVectors)) {
        it(`aggregates keys ${name}`, function () {
          const publicKeys = vector.publicKeyIndices.map((i) => basePublicKeys[i]);
          const key = musig.keyAgg(publicKeys, { sort: false });
          expect(Buffer.from(key.publicKey).toString('hex')).toBe(vector.expected);
          const secondPublicKeyX = Buffer.from(key.keyAggSession.rest.subarray(65, 97)).toString(
            'hex'
          );
          if ('secondPublicKeyIndex' in vector) {
            expect(secondPublicKeyX).toBe(publicKeys[vector.secondPublicKeyIndex].toString('hex'));
          } else {
            expect(secondPublicKeyX).toBe(Buffer.alloc(32).toString('hex'));
          }
        });
      }
    });

    describe('nonceGen vectors', function () {
      for (const [name, vector] of Object.entries(vectors.nonceVectors)) {
        it(`generates nonces ${name}`, function () {
          const args = { ...nonceArgs };
          vector.blankArgs.forEach((i) => delete (args as Record<string, Uint8Array>)[i]);
          const nonce = musig.nonceGen(args);
          expect(Buffer.from(nonce.secretNonce).toString('hex')).toBe(vector.expected);
        });
      }
    });

    describe('nonceAgg vectors', function () {
      for (const [name, vector] of Object.entries(vectors.nonceAggVectors)) {
        it(`aggregatesNonces ${name}`, function () {
          const nonces = vector.publicNonces.map((nonce) => Buffer.from(nonce, 'hex'));
          const aggNonce = musig.nonceAgg(nonces);
          expect(Buffer.from(aggNonce).toString('hex')).toBe(vector.expected);
        });
      }
    });

    describe('sign vectors', function () {
      for (const [name, vector] of Object.entries(vectors.signVectors)) {
        const { msg, secretNonce, aggNonce, secretKey, nonSignerKeyIndices } = vectors.signData;
        it(`partial signs ${name}`, function () {
          const publicKeys: Uint8Array[] = nonSignerKeyIndices.map((i) => basePublicKeys[i]);
          const signingPublicKey = noble.schnorr.getPublicKey(secretKey);
          publicKeys.splice(vector.signerIndex, 0, signingPublicKey);

          let parity, keyAggSession;
          if ('tweak' in vector) {
            ({ parity, keyAggSession } = musig.keyAgg(publicKeys, {
              tweaks: [Buffer.from(vector.tweak, 'hex')],
              tweaksXOnly: [vector.xOnlyTweak],
              sort: false,
            }));
          } else {
            ({ parity, keyAggSession } = musig.keyAgg(publicKeys, { sort: false }));
          }
          expect(parity).toBe(vector.expectedParity);

          const { sig, signingSession } = musig.partialSign({
            msg: Buffer.from(msg, 'hex'),
            secretKey: Buffer.from(secretKey, 'hex'),
            nonce: { secretNonce: Buffer.from(secretNonce, 'hex') },
            aggNonce: Buffer.from(aggNonce, 'hex'),
            keyAggSession,
          });
          expect(Buffer.from(sig).toString('hex')).toBe(vector.expectedS);
          expect(crypto.hasEvenY(signingSession.slice(0, 65)) ? 0 : 1).toBe(
            vector.expectedNonceParity
          );
        });
      }
    });

    describe('keyAggSession', function () {
      const { keyAggSession } = musig.keyAgg([
        noble.schnorr.getPublicKey(noble.utils.randomPrivateKey()),
      ]);
      const tweaks = [validTweak];

      it('rejects wrong base length', function () {
        const session = { ...keyAggSession, base: new Uint8Array(31) };
        expect(() => musig.addTweaks(session, tweaks)).toThrow();
      });

      it('rejects wrong rest length', function () {
        const session = { ...keyAggSession, rest: new Uint8Array(131) };
        expect(() => musig.addTweaks(session, tweaks)).toThrow();
      });

      it('rejects non-point public key', function () {
        const rest = Uint8Array.from(keyAggSession.rest);
        rest.set(invalidPoint, 0);
        expect(() => musig.addTweaks({ ...keyAggSession, rest }, tweaks)).toThrow();
      });

      it('rejects invalid second public key x', function () {
        const rest = Uint8Array.from(keyAggSession.rest);
        rest.set(invalidX, 65);
        expect(() => musig.addTweaks({ ...keyAggSession, rest }, tweaks)).toThrow();
      });

      it('rejects invalid tweak', function () {
        const rest = Uint8Array.from(keyAggSession.rest);
        rest.set(notSecret, 98);
        expect(() => musig.addTweaks({ ...keyAggSession, rest }, tweaks)).toThrow();
      });
    });

    describe('signingSession', function () {
      const { keyAggSession } = musig.keyAgg([validX]);
      const aggNonce = new Uint8Array(66);
      aggNonce.set(noble.getPublicKey(noble.utils.randomPrivateKey(), true), 0);
      aggNonce.set(noble.getPublicKey(noble.utils.randomPrivateKey(), true), 33);
      const msg = noble.utils.randomBytes();
      const sigs = [noble.utils.randomBytes()];
      const signingSession = musig.createSigningSession(aggNonce, msg, keyAggSession);

      it('rejects wrong length', function () {
        expect(() => musig.signAgg(sigs, new Uint8Array(160))).toThrow();
      });

      it('rejects non-point final nonce', function () {
        const invalidSession = Uint8Array.from(signingSession);
        invalidSession.set(invalidPoint, 0);
        expect(() => musig.signAgg(sigs, invalidSession)).toThrow();
      });

      it('rejects invalid coefficient', function () {
        const invalidSession = Uint8Array.from(signingSession);
        invalidSession.set(notSecret, 65);
        expect(() => musig.signAgg(sigs, invalidSession)).toThrow();
      });

      it('rejects invalid challenge', function () {
        const invalidSession = Uint8Array.from(signingSession);
        invalidSession.set(notSecret, 97);
        expect(() => musig.signAgg(sigs, invalidSession)).toThrow();
      });

      it('rejects invalid sPart', function () {
        const invalidSession = Uint8Array.from(signingSession);
        invalidSession.set(notSecret, 129);
        expect(() => musig.signAgg(sigs, invalidSession)).toThrow();
      });
    });

    describe('keyAgg errors', function () {
      it('rejects wrong length', function () {
        expect(() => musig.keyAgg([new Uint8Array(31)])).toThrow();
      });

      it('rejects one wrong length', function () {
        expect(() => musig.keyAgg([validX, new Uint8Array(31)])).toThrow();
      });

      it('rejects one invalid X', function () {
        expect(() => musig.keyAgg([validX, invalidX])).toThrow();
      });

      it('rejects no keys', function () {
        expect(() => musig.keyAgg([])).toThrow();
      });
    });

    describe('addTweaks errors', function () {
      const { keyAggSession } = musig.keyAgg([validX]);

      it('rejects wrong length', function () {
        expect(() => musig.addTweaks(keyAggSession, [validTweak], [false, true])).toThrow();
      });
    });

    describe('nonceGen errors', function () {
      it('rejects wrong length', function () {
        expect(() => musig.nonceGen({ ...nonceArgs, sessionId: new Uint8Array(31) })).toThrow();
        expect(() => musig.nonceGen({ ...nonceArgs, secretKey: new Uint8Array(31) })).toThrow();
        expect(() => musig.nonceGen({ ...nonceArgs, msg: new Uint8Array(31) })).toThrow();
        expect(() =>
          musig.nonceGen({ ...nonceArgs, aggregatePublicKey: new Uint8Array(31) })
        ).toThrow();
        expect(() => musig.nonceGen({ ...nonceArgs, extraInput: new Uint8Array(31) })).toThrow();
      });
    });

    describe('partialSign errors', function () {
      it('rejects bad secretKey', function () {
        expect(() =>
          musig.partialSign({
            msg: noble.utils.randomBytes(),
            secretKey: notSecret,
            nonce: { secretNonce: noble.utils.randomBytes(64) },
            aggNonce: noble.utils.randomBytes(66),
            keyAggSession: { base: new Uint8Array(32), rest: new Uint8Array(130) },
            signingSession: new Uint8Array(161),
          })
        ).toThrow();
      });
    });
  });
}
