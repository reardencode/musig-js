import * as nc from 'node:crypto';
import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { hashToPrivateScalar } from '@noble/curves/abstract/modular';
import { numberToBytesBE } from '@noble/curves/abstract/utils';
import { KeyGenContext, MuSigFactory, SessionKey } from '../index';
import { nobleCrypto, tinyCrypto } from './utils';
import * as det_sign_vectors from './bip-vectors/det_sign_vectors.json';
import * as key_sort_vectors from './bip-vectors/key_sort_vectors.json';
import * as nonce_gen_vectors from './bip-vectors/nonce_gen_vectors.json';
import * as sign_verify_vectors from './bip-vectors/sign_verify_vectors.json';
import * as key_agg_vectors from './bip-vectors/key_agg_vectors.json';
import * as nonce_agg_vectors from './bip-vectors/nonce_agg_vectors.json';
import * as sig_agg_vectors from './bip-vectors/sig_agg_vectors.json';
import * as tweak_vectors from './bip-vectors/tweak_vectors.json';

interface Signer {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  publicNonce?: Uint8Array;
  sig?: Uint8Array;
}
function randomBytes(n = 32): Uint8Array {
  const ret = new Uint8Array(n);
  nc.randomFillSync(ret);
  return ret;
}
function randomPrivateKey(): Uint8Array {
  const rand = randomBytes(secp256k1.CURVE.Fp.BYTES + 8);
  const d = hashToPrivateScalar(rand, secp256k1.CURVE.n);
  return numberToBytesBE(d, secp256k1.CURVE.Fp.BYTES);
}

const validPub = secp256k1.getPublicKey(randomPrivateKey(), true);
const invalidPub = Buffer.from(
  '02a02b2026e3b9c3842684d892cd8cf3a30530c21ec6d75d1d03ed9f4f536af692',
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
const validTweak = randomPrivateKey();

const nonceArgs = {
  sessionId: Buffer.from(nonce_gen_vectors.test_cases[0].rand_, 'hex'),
  secretKey: Buffer.from(nonce_gen_vectors.test_cases[0].sk || '', 'hex'),
  publicKey: Buffer.from(nonce_gen_vectors.test_cases[0].pk || '', 'hex'),
  msg: Buffer.from(nonce_gen_vectors.test_cases[0].msg || '', 'hex'),
  aggregatePublicKey: Buffer.from(nonce_gen_vectors.test_cases[0].aggpk || '', 'hex'),
  extraInput: Buffer.from(nonce_gen_vectors.test_cases[0].extra_in || '', 'hex'),
};

const tweaks = new Array(5).fill(0).map((_, i) => {
  const tweak = randomPrivateKey();
  return { tweak, xOnly: (tweak[i] & 1) === 1 };
});
const cryptos = [
  { cryptoName: 'noble', crypto: nobleCrypto },
  { cryptoName: 'tiny', crypto: tinyCrypto },
];

for (const { cryptoName, crypto } of cryptos) {
  describe(cryptoName, function () {
    const musig = MuSigFactory(crypto);

    for (let nSigners = 1; nSigners < 5; nSigners++)
      describe(`random musig(${nSigners})`, function () {
        let keyGenContext: KeyGenContext;
        let signers: Signer[] = [];
        let msg = randomBytes();
        let aggNonce: Uint8Array;
        let sessionKey: SessionKey;
        let sig: Uint8Array;

        beforeAll(function () {
          for (let i = 0; i < nSigners; i++) {
            const secretKey = randomPrivateKey();
            const publicKey = secp256k1.getPublicKey(secretKey, true);
            signers.push({ secretKey, publicKey });
          }
        });

        it('aggregates keys', function () {
          keyGenContext = musig.keyAgg(signers.map(({ publicKey }) => publicKey));
        });

        for (let i = -1; i < tweaks.length; i++) {
          describe(`tweak(${i})`, function () {
            if (i >= 0) {
              it('tweaks a key', function () {
                keyGenContext = musig.addTweaks(keyGenContext, ...tweaks.slice(i, i + 1));
              });
            }

            it('makes nonces', function () {
              const publicKey = musig.getXOnlyPubkey(keyGenContext);
              for (let j = 0; j < signers.length; j++) {
                const signer = signers[j];
                switch (j) {
                  case 1:
                    const sessionId = new Uint8Array(32);
                    sessionId[31] = nSigners;
                    signer.publicNonce = musig.nonceGen({
                      sessionId,
                      secretKey: signer.secretKey,
                      publicKey: signer.publicKey,
                      msg,
                      xOnlyPublicKey: publicKey,
                    });
                    break;
                  case 2:
                    signer.publicNonce = musig.nonceGen({
                      sessionId: randomBytes(),
                      secretKey: signer.secretKey,
                      publicKey: signer.publicKey,
                      msg,
                      xOnlyPublicKey: publicKey,
                    });
                    break;
                  case 3:
                    signer.publicNonce = musig.nonceGen({
                      sessionId: randomBytes(),
                      secretKey: signer.secretKey,
                      publicKey: signer.publicKey,
                      msg,
                      xOnlyPublicKey: publicKey,
                      extraInput: randomBytes(),
                    });
                    break;
                  default:
                    signer.publicNonce = musig.nonceGen({
                      publicKey: signer.publicKey,
                    });
                    break;
                }
              }
            });

            it('aggregates nonces', function () {
              aggNonce = musig.nonceAgg(signers.map(({ publicNonce }) => publicNonce!));
            });

            it('starts a signing sesion', function () {
              sessionKey = musig.startSigningSession(
                aggNonce,
                msg,
                signers.map(({ publicKey }) => publicKey),
                ...tweaks.slice(0, i + 1)
              );
            });

            it(`makes partial sigs ${signers.length % 2 === 1 ? 'w/verify' : ''}`, function () {
              for (const signer of signers) {
                const sig = musig.partialSign({
                  secretKey: signer.secretKey,
                  publicNonce: signer.publicNonce!,
                  sessionKey,
                  verify: signers.length % 2 === 1,
                });
                signer.sig = sig;
              }
            });

            it(`verifies partial sigs`, function () {
              for (const signer of signers) {
                const result = musig.partialVerify({
                  sig: signer.sig!,
                  publicKey: signer.publicKey,
                  publicNonce: signer.publicNonce!,
                  sessionKey,
                });
                if (!result) throw new Error('Expected result to be truthy');
              }
            });

            it('aggregates sigs', function () {
              sig = musig.signAgg(
                signers.map(({ sig }) => sig!),
                sessionKey
              );
            });

            it('verifies sig', function () {
              const publicKey = musig.getXOnlyPubkey(keyGenContext);
              expect(schnorr.verify(sig, msg, publicKey)).toBe(true);
            });
          });
        }
      });

    // TODO: key_sort_vectors
    describe('keyAgg vectors', function () {
      const { pubkeys, tweaks, valid_test_cases, error_test_cases } = key_agg_vectors;
      valid_test_cases.forEach(({ key_indices, expected }, index) => {
        it(`aggregates keys ${index}`, function () {
          const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
          const keyGenContext = musig.keyAgg(publicKeys);
          const actual = musig.getXOnlyPubkey(keyGenContext);
          expect(Buffer.from(actual).toString('hex')).toBe(expected.toLowerCase());
        });
      });

      error_test_cases.forEach(
        ({ key_indices, tweak_indices, is_xonly, error, comment }, index) => {
          it(`fails to aggregate keys ${index} "${comment || ''}"`, function () {
            const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
            const tweaksI = tweak_indices.map((i) => Buffer.from(tweaks[i], 'hex'));
            try {
              musig.keyAgg(publicKeys);
              fail();
            } catch (e) {
              // TODO: Maybe check the messages, but they're different from the public fixtures
              expect(e instanceof Error).toBe(true);
            }
          });
        }
      );
    });

    describe('tweak vectors', function () {
      const {
        sk,
        pubkeys,
        secnonce,
        pnonces,
        aggnonce,
        tweaks,
        msg,
        valid_test_cases,
        error_test_cases,
      } = tweak_vectors;

      valid_test_cases.forEach(
        (
          { key_indices, nonce_indices, tweak_indices, is_xonly, signer_index, comment, expected },
          index
        ) => {
          it(`tweaks and signs ${index} "${comment || ''}"`, function () {
            const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
            const tweaksI = tweak_indices.map((i) => ({
              tweak: Buffer.from(tweaks[i], 'hex'),
              xOnly: is_xonly[i],
            }));

            const message = Buffer.from(msg, 'hex');
            const nonces = nonce_indices.map((i) => Buffer.from(pnonces[i], 'hex'));
            const aggNonce = musig.nonceAgg(nonces);
            expect(Buffer.from(aggNonce).toString('hex')).toBe(aggnonce.toLowerCase());
            const secNonce = Buffer.from(secnonce, 'hex');
            const sessionKey = musig.startSigningSession(aggNonce, message, publicKeys, ...tweaksI);
            musig.addExternalNonce(nonces[signer_index], Buffer.from(secnonce, 'hex'));
            const sig = musig.partialSign({
              secretKey: Buffer.from(sk, 'hex'),
              publicNonce: nonces[signer_index],
              sessionKey,
              verify: false,
            });
            expect(Buffer.from(sig).toString('hex')).toBe(expected.toLowerCase());

            const result = musig.partialVerify({
              sig,
              publicKey: publicKeys[signer_index],
              publicNonce: nonces[signer_index],
              sessionKey,
            });
            expect(result).toBeTruthy();
          });
        }
      );

      error_test_cases.forEach(
        ({ key_indices, tweak_indices, is_xonly, error, comment }, index) => {
          it(`fails to tweak key ${index} "${comment || ''}"`, function () {
            const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
            const tweaksI = tweak_indices.map((i) => ({
              tweak: Buffer.from(tweaks[i], 'hex'),
              xOnly: is_xonly[i],
            }));
            try {
              musig.keyAgg(publicKeys, ...tweaksI);
              fail();
            } catch (e) {
              // TODO: Maybe check the messages, but they're different from the public fixtures
              expect(e instanceof Error).toBe(true);
            }
          });
        }
      );
    });

    describe('nonceGen vectors', function () {
      nonce_gen_vectors.test_cases.forEach(
        ({ rand_, sk, pk, aggpk, msg, extra_in, expected }, index) => {
          it(`generates nonces ${index}`, function () {
            const args = {
              sessionId: Buffer.from(rand_, 'hex'),
              secretKey: sk === null ? undefined : Buffer.from(sk, 'hex'),
              publicKey: Buffer.from(pk, 'hex'),
              xOnlyPublicKey: aggpk === null ? undefined : Buffer.from(aggpk, 'hex'),
              msg: msg === null ? undefined : Buffer.from(msg, 'hex'),
              extraInput: extra_in === null ? undefined : Buffer.from(extra_in, 'hex'),
            };
            const publicNonce = musig.nonceGen(args);
            const secretNonces = [
              Buffer.from(expected.substring(0, 64), 'hex'),
              Buffer.from(expected.substring(64, 128), 'hex'),
            ];
            const expectedNonce = Buffer.concat(
              secretNonces.map((s) => Buffer.from(secp256k1.getPublicKey(s, true)))
            );
            expect(Buffer.from(publicNonce).toString('hex')).toBe(expectedNonce.toString('hex'));
          });
        }
      );
    });

    describe('nonceAgg vectors', function () {
      const {
        pnonces,
        valid_test_cases,
        error_test_cases, // TODO
      } = nonce_agg_vectors;
      valid_test_cases.forEach(({ pnonce_indices, expected, comment }, index) => {
        it(`aggregatesNonces ${index} "${comment || ''}"`, function () {
          const nonces = pnonce_indices.map((i) => Buffer.from(pnonces[i], 'hex'));
          const aggNonce = musig.nonceAgg(nonces);
          expect(Buffer.from(aggNonce).toString('hex')).toBe(expected.toLowerCase());
        });
      });
    });

    describe('sign vectors', function () {
      const {
        sk,
        pubkeys,
        secnonces,
        pnonces,
        aggnonces,
        msgs,
        valid_test_cases,
        sign_error_test_cases, // TODO
        verify_fail_test_cases, // TODO
        verify_error_test_cases, // TODO
      } = sign_verify_vectors;

      it('checks public key', function () {
        const publicKey = secp256k1.getPublicKey(sk, true);
        expect(Buffer.from(publicKey).toString('hex')).toEqual(pubkeys[0].toLowerCase());
      });

      valid_test_cases.forEach(
        (
          {
            key_indices,
            nonce_indices,
            aggnonce_index,
            msg_index,
            signer_index,
            expected,
            comment,
          },
          index
        ) => {
          it(`partial signs ${index} "${comment || ''}"`, function () {
            const publicKeys: Uint8Array[] = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
            const pubNonces: Uint8Array[] = nonce_indices.map((i) =>
              Buffer.from(pnonces[i], 'hex')
            );

            const aggNonce = musig.nonceAgg(pubNonces);
            expect(Buffer.from(aggNonce).toString('hex')).toEqual(
              aggnonces[aggnonce_index].toLowerCase()
            );

            const msg = Buffer.from(msgs[msg_index], 'hex');

            const sessionKey = musig.startSigningSession(aggNonce, msg, publicKeys);
            musig.addExternalNonce(pubNonces[signer_index], Buffer.from(secnonces[0], 'hex'));
            const sig = musig.partialSign({
              secretKey: Buffer.from(sk, 'hex'),
              publicNonce: pubNonces[signer_index],
              sessionKey,
              verify: false,
            });

            expect(Buffer.from(sig).toString('hex')).toBe(expected.toLowerCase());

            const result = musig.partialVerify({
              sig,
              publicKey: publicKeys[signer_index],
              publicNonce: pubNonces[signer_index],
              sessionKey,
            });
            expect(result).toBeTruthy();
          });
        }
      );
    });

    describe('deterministic sign vectors', function () {
      const {
        sk,
        pubkeys,
        msgs,
        valid_test_cases,
        error_test_cases, // TODO
      } = det_sign_vectors;

      const secretKey = Buffer.from(sk, 'hex');
      let publicKey: Uint8Array;

      it('checks public key', function () {
        publicKey = secp256k1.getPublicKey(secretKey, true);
        expect(Buffer.from(publicKey).toString('hex')).toEqual(pubkeys[0].toLowerCase());
      });

      valid_test_cases.forEach(
        (
          {
            rand,
            aggothernonce,
            key_indices,
            tweaks,
            is_xonly,
            msg_index,
            signer_index,
            expected,
            comment,
          },
          index
        ) => {
          const message = Buffer.from(msgs[msg_index], 'hex');
          const aggOtherNonce = Buffer.from(aggothernonce, 'hex');
          const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
          const tweaksI = tweaks.map((t, i) => ({
            tweak: Buffer.from(t, 'hex'),
            xOnly: is_xonly[i],
          }));

          let nonce: { publicNonce: Uint8Array };

          it(`generates nonce only ${index} "${comment || ''}"`, function () {
            nonce = musig.deterministicNonceGen({
              secretKey,
              aggOtherNonce,
              publicKeys,
              tweaks: tweaksI,
              msg: message,
              rand: rand === null ? undefined : Buffer.from(rand, 'hex'),
            });

            expect(Buffer.from(nonce.publicNonce).toString('hex')).toBe(expected[0].toLowerCase());
          });

          it(`signs ${index} "${comment || ''}"`, function () {
            const { sig, publicNonce, sessionKey } = musig.deterministicSign({
              secretKey,
              aggOtherNonce,
              publicKeys,
              tweaks: tweaksI,
              msg: message,
              rand: rand === null ? undefined : Buffer.from(rand, 'hex'),
              verify: false,
            });

            expect(Buffer.from(publicNonce).toString('hex')).toBe(expected[0].toLowerCase());

            if (sig === undefined) throw new Error('Expected sig');
            expect(Buffer.from(sig).toString('hex')).toBe(expected[1].toLowerCase());

            if (sessionKey === undefined) throw new Error('Expected sessionKey');
            const result = musig.partialVerify({
              sig,
              publicKey: publicKeys[signer_index],
              publicNonce,
              sessionKey,
            });
            expect(result).toBeTruthy();
          });
        }
      );
    });

    describe('sig agg vectors', function () {
      const {
        pubkeys,
        pnonces,
        tweaks,
        psigs,
        msg,
        valid_test_cases,
        error_test_cases, // TODO
      } = sig_agg_vectors;
      const message = Buffer.from(msg, 'hex');
      valid_test_cases.forEach(
        (
          { aggnonce, nonce_indices, key_indices, tweak_indices, is_xonly, psig_indices, expected },
          index
        ) => {
          it(`aggregates signatures ${index}`, function () {
            const pubNonces = nonce_indices.map((i) => Buffer.from(pnonces[i], 'hex'));
            const aggNonce = musig.nonceAgg(pubNonces);
            expect(Buffer.from(aggNonce).toString('hex')).toEqual(aggnonce.toLowerCase());

            const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
            const tweaksI = tweak_indices.map((i) => ({
              tweak: Buffer.from(tweaks[i], 'hex'),
              xOnly: is_xonly[i],
            }));
            const partialSigs = psig_indices.map((i) => Buffer.from(psigs[i], 'hex'));

            const sessionKey = musig.startSigningSession(aggNonce, message, publicKeys, ...tweaksI);
            const sig = musig.signAgg(partialSigs, sessionKey);

            expect(Buffer.from(sig).toString('hex')).toEqual(expected.toLowerCase());

            const aggPk = musig.getXOnlyPubkey(sessionKey);
            // Something in signAgg, nonce processing, or maybe key aggregation broken
            expect(schnorr.verify(sig, message, aggPk)).toBe(true);
          });
        }
      );
    });

    //    describe('keyGenContext', function () {
    //      const keyGenContext = musig.keyAgg([
    //        secp256k1.getPublicKey(randomPrivateKey(), true),
    //      ]);
    //      const tweaks = [validTweak];
    //
    //      it('rejects wrong base length', function () {
    //        const ctx = { ...keyGenContext, base: new Uint8Array(31) };
    //        expect(() => musig.addTweaks(ctx, tweaks)).toThrow();
    //      });
    //
    //      it('rejects wrong rest length', function () {
    //        const ctx = { ...keyGenContext, base: new Uint8Array(31) };
    //        expect(() => musig.addTweaks(ctx, tweaks)).toThrow();
    //      });
    //
    //      it('rejects non-point public key', function () {
    //        const rest = Uint8Array.from(keyGenContext.rest);
    //        rest.set(invalidPoint, 0);
    //        expect(() => musig.addTweaks({ ...keyGenContext, rest }, tweaks)).toThrow();
    //      });
    //
    //      it('rejects invalid second public key', function () {
    //        const rest = Uint8Array.from(keyGenContext.rest);
    //        rest.set(invalidPub, 65);
    //        expect(() => musig.addTweaks({ ...keyGenContext, rest }, tweaks)).toThrow();
    //      });
    //
    //      it('rejects invalid tweak', function () {
    //        const rest = Uint8Array.from(keyGenContext.rest);
    //        rest.set(notSecret, 99);
    //        expect(() => musig.addTweaks({ ...keyGenContext, rest }, tweaks)).toThrow();
    //      });
    //    });

    //    describe('signingSession', function () {
    //      const keyGenContext = musig.keyAgg([validPub]);
    //      const aggNonce = new Uint8Array(66);
    //      aggNonce.set(secp256k1.getPublicKey(randomPrivateKey(), true), 0);
    //      aggNonce.set(secp256k1.getPublicKey(randomPrivateKey(), true), 33);
    //      const msg = randomBytes();
    //      const sigs = [randomBytes()];
    //      const signingSession = musig.createSigningSession(aggNonce, msg, keyGenContext);
    //
    //      it('rejects wrong length', function () {
    //        expect(() => musig.createSigningSession(new Uint8Array(65), msg, keyGenContext)).toThrow(
    //          /Invalid aggNonce length/
    //        );
    //        expect(() => musig.signAgg(sigs, keyGenContext, new Uint8Array(160))).toThrow(
    //          /Invalid signingSession length/
    //        );
    //      });
    //
    //      it('rejects non-point final nonce', function () {
    //        const invalidSession = Uint8Array.from(signingSession);
    //        invalidSession.set(invalidPoint, 0);
    //        expect(() => musig.signAgg(sigs, keyGenContext, invalidSession)).toThrow();
    //      });
    //
    //      it('rejects invalid coefficient', function () {
    //        const invalidSession = Uint8Array.from(signingSession);
    //        invalidSession.set(notSecret, 65);
    //        expect(() => musig.signAgg(sigs, keyGenContext, invalidSession)).toThrow();
    //      });
    //
    //      it('rejects invalid challenge', function () {
    //        const invalidSession = Uint8Array.from(signingSession);
    //        invalidSession.set(notSecret, 97);
    //        expect(() => musig.signAgg(sigs, keyGenContext, invalidSession)).toThrow();
    //      });
    //    });

    describe('keyAgg errors', function () {
      it('rejects wrong length', function () {
        expect(() => musig.keyAgg([new Uint8Array(31)])).toThrow();
      });

      it('rejects one wrong length', function () {
        expect(() => musig.keyAgg([validPub, new Uint8Array(31)])).toThrow();
      });

      it('rejects one invalid key', function () {
        expect(() => musig.keyAgg([validPub, invalidPub])).toThrow();
      });

      it('rejects no keys', function () {
        expect(() => musig.keyAgg([])).toThrow();
      });
    });

    describe('addTweaks', function () {
      const keyGenContext = musig.keyAgg([validPub]);

      it('performs ordinary tweaking if xOnly omitted', function () {
        const k1 = musig.addTweaks(keyGenContext, validTweak);
        const k2 = musig.addTweaks(keyGenContext, { tweak: validTweak, xOnly: false });
        expect(Buffer.from(k1.aggPublicKey)).toEqual(Buffer.from(k2.aggPublicKey));
      });
    });

    describe('nonceGen errors', function () {
      it('rejects wrong length', function () {
        expect(() => musig.nonceGen({ ...nonceArgs, sessionId: new Uint8Array(31) })).toThrow();
        expect(() => musig.nonceGen({ ...nonceArgs, secretKey: new Uint8Array(31) })).toThrow();
        expect(() => musig.nonceGen({ ...nonceArgs, publicKey: new Uint8Array(31) })).toThrow();
        expect(() =>
          musig.nonceGen({ ...nonceArgs, xOnlyPublicKey: new Uint8Array(31) })
        ).toThrow();
        expect(() =>
          musig.nonceGen({ ...nonceArgs, extraInput: new Uint8Array(Math.pow(2, 32)) })
        ).toThrow();
      });
    });

    describe('partialSign errors', function () {
      const aggNonce = new Uint8Array(66);
      aggNonce.set(secp256k1.getPublicKey(randomPrivateKey(), true), 0);
      aggNonce.set(secp256k1.getPublicKey(randomPrivateKey(), true), 33);
      const sessionKey = musig.startSigningSession(aggNonce, randomBytes(), [validPub]);
      const secretNonce = new Uint8Array(97);
      const fakePublicNonce = new Uint8Array(66);
      secretNonce.set(randomPrivateKey(), 0);
      secretNonce.set(randomPrivateKey(), 32);
      secretNonce.set(validPub, 64);

      for (const badNonceI of [0, 1]) {
        it('rejects bad secretNonce', function () {
          const invalidSecretNonce = Uint8Array.from(secretNonce);
          invalidSecretNonce.set(notSecret, badNonceI * 32);

          expect(() => {
            musig.addExternalNonce(fakePublicNonce, invalidSecretNonce);
            musig.partialSign({
              secretKey: randomPrivateKey(),
              publicNonce: fakePublicNonce,
              sessionKey,
            });
          }).toThrow(/Invalid secretNonce/);
        });
      }

      it('rejects bad secretKey', function () {
        musig.addExternalNonce(fakePublicNonce, secretNonce);
        expect(() =>
          musig.partialSign({
            secretKey: notSecret,
            publicNonce: fakePublicNonce,
            sessionKey,
          })
        ).toThrow(/Invalid secretKey/);
      });
    });
  });
}
