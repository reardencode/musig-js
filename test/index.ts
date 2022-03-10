import * as fc from 'fast-check';
import { schnorr, utils } from '@noble/secp256k1';
import * as musig from '..';
import * as vectors from './vectors.json';

interface Signer {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  noncePair?: { privateNonce?: Uint8Array; publicNonce: Uint8Array };
  sig?: musig.MusigPartialSig;
}

const tweaks = new Array(5).fill(0).map(() => utils.randomPrivateKey());

for (let nSigners = 1; nSigners < 5; nSigners++) {
  describe(`random musig(${nSigners})`, function() {

    let publicKey: musig.MusigPublicKey;
    let signers: Signer[] = [];
    let message = utils.randomBytes();
    let aggNonce: Uint8Array;
    let sig: Uint8Array;

    beforeAll(function() {
      for (let i = 0; i < nSigners; i++) {
        const privateKey = utils.randomPrivateKey();
        const publicKey = schnorr.getPublicKey(privateKey);
        signers.push({ privateKey, publicKey });
      }
    });

    it('aggregates keys', async function() {
      publicKey = await musig.keyAgg(
        signers.map(({ publicKey }) => publicKey),
        { tweak: nSigners % 2 === 1 ? tweaks[0] : undefined }
      );
    });

    for (let i = 0; i < tweaks.length; i++) {

      describe(`tweak(${i})`, function() {

        if (i !== 0) {
          it('tweaks a key', function() {
            publicKey = musig.tweak(publicKey.keyAggCache, tweaks[i], i === nSigners % 3);
          });
        }

        it('makes nonces', async function() {
          for (let j = 0; j < signers.length; j++) {
            const signer = signers[j];
            switch (j) {
              case 1:
                const sessionId = new Uint8Array(32);
                sessionId[31] = nSigners;
                signer.noncePair =
                  await musig.nonceGen(sessionId, signer.privateKey, message, publicKey.publicKey);
                break;
              case 2:
                signer.noncePair =
                  await musig.nonceGen(undefined, signer.privateKey, message, publicKey.publicKey);
                break;
              case 3:
                signer.noncePair = await musig.nonceGen(
                  undefined,
                  signer.privateKey,
                  message,
                  publicKey.publicKey,
                  utils.randomBytes()
                );
                break;
              default:
                signer.noncePair = await musig.nonceGen();
                break;
            }
          }
        });

        it('aggregates nonces', function() {
          aggNonce = musig.nonceAgg(signers.map(({noncePair}) => noncePair!.publicNonce));
        });

        it('makes partial sigs', async function() {
          for (const signer of signers) {
            signer.sig = await musig.partialSign(
              message,
              signer.privateKey,
              { privateNonce: signer.noncePair!.privateNonce!, publicNonce: signer.noncePair!.publicNonce },
              aggNonce,
              publicKey.keyAggCache
            );
            delete signer.noncePair!.privateNonce;
          }
        });

        it('verifies partial sigs', async function() {
          for (const signer of signers) {
            expect(await musig.partialVerify(
              signer.sig!.sig,
              message,
              signer.publicKey,
              signer.noncePair!.publicNonce,
              aggNonce,
              publicKey.keyAggCache
            )).toBeTruthy();
          }
        });

        // TODO: it('verifies partial sigs w/ session', function() { });
        //
        it('aggregates sigs', function() {
          sig = musig.signAgg(signers.map(({ sig }) => sig!.sig), signers[0].sig!.session);
        });

        it('verifies sig', async function() {
          expect(await schnorr.verify(sig, message, publicKey.publicKey)).toBe(true);
        });
      });
    }
  });
}

describe('keyAgg vectors', function() {
  for (const [name, vector] of Object.entries(vectors.keyAggVectors)) {
    it(`aggregates keys ${name}`, async function() {
      const publicKeys = vector.publicKeyIndices.map((i) => vectors.publicKeys[i]);
      const key = await musig.keyAgg(publicKeys, { sort: false });
      expect(Buffer.from(key.publicKey).toString('hex')).toBe(vector.expected);
      const secondPublicKey = key.keyAggCache.slice((33 + 32) * 2, (33 + 32 + 32) * 2);
      if ('secondPublicKeyIndex' in vector) {
        expect(secondPublicKey).toBe(publicKeys[vector.secondPublicKeyIndex]);
      } else {
        expect(secondPublicKey).toBe(new Array(65).join('0'));
      }
    });
  }
});

describe('nonceGen vectors', function() {
  for (const [name, vector] of Object.entries(vectors.nonceVectors)) {
    it(`generates nonces ${name}`, async function() {
      const args: Array<string | undefined> = [...vectors.nonceArgs];
      vector.blankArgs.forEach((i) => args[i] = undefined);
      const nonce = await musig.nonceGen(...args);
      expect(Buffer.from(nonce.privateNonce).toString('hex')).toBe(vector.expected);
    });
  }
});

describe('sign vectors', function() {
  for (const [name, vector] of Object.entries(vectors.signVectors)) {
    const { msg, privateNonce, aggNonce, signingKey, nonSignerKeyIndices } = vectors.signData;
    it(`partial signs ${name}`, async function() {
      const publicKeys: Array<string | Uint8Array> = nonSignerKeyIndices.map((i) => vectors.publicKeys[i]);
      const signingPublicKey = schnorr.getPublicKey(signingKey);
      publicKeys.splice(vector.signerIndex, 0, signingPublicKey);

      let parity, keyAggCache;
      if ('tweak' in vector) {
        ({ parity, keyAggCache } = await musig.keyAgg(
          publicKeys,
          { tweak: vector.tweak, xOnlyTweak: vector.xOnlyTweak, sort: false}
        ));
      } else {
        ({ parity, keyAggCache } = await musig.keyAgg(publicKeys, { sort: false }));
      }
      expect(parity).toBe(vector.expectedParity);

      const { sig, session } = await musig.partialSign(msg, signingKey, {privateNonce}, aggNonce, keyAggCache);
      expect(Buffer.from(sig).toString('hex')).toBe(vector.expectedS);
      expect(Buffer.from(session, 'hex')[0]).toBe(vector.expectedNonceParity);
    });
  }
});
