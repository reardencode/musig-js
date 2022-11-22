import { Crypto, MuSigFactory } from '..';
import { nobleCrypto, tinyCrypto } from './utils';
import * as secp from '@noble/secp256k1';
import createHmac = require('create-hmac');
import * as vectors from './bip-vectors/key_agg_vectors.json';

const { run, mark, logMem } = require('micro-bmark');

const cryptos = [
  { cryptoName: 'noble', crypto: nobleCrypto },
  { cryptoName: 'tiny', crypto: tinyCrypto },
];

secp.utils.hmacSha256Sync = (key, ...msgs) => {
  const h = createHmac('sha256', Buffer.from(key));
  msgs.forEach((msg) => h.update(msg));
  return h.digest();
};

// run([4, 8, 16], async (windowSize) => {
run(cryptos, async ({ cryptoName, crypto }: { cryptoName: string; crypto: Crypto }) => {
  const musig = MuSigFactory(crypto);

  logMem();
  console.log();

  const vectorPublicKeys: Uint8Array[] = vectors.pubkeys.map((pk) => Buffer.from(pk, 'hex'));

  await mark('tohex', 1000, async () => {
    return Buffer.from(vectorPublicKeys[0]).toString('hex');
  });

  const pubKeyHash = Buffer.from(vectors.tweaks[0], 'hex');
  await mark('taggedHash', 1000, async () => {
    return crypto.taggedHash('KeyAgg coefficient', pubKeyHash, vectorPublicKeys[0]);
  });
  //
  //  await mark('keyAgg(2)', 500, async () => {
  //    return musig.keyAgg(vectorPublicKeys.slice(1));
  //  });
  //  await mark('keyAgg(3)', 400, async () => {
  //    return musig.keyAgg(vectorPublicKeys);
  //  });
  //  await mark('keyAgg(5)', 250, async () => {
  //    return musig.keyAgg(vectorPublicKeys.concat(vectorPublicKeys.slice(1)));
  //  });
  //
  //  const msg = Buffer.from(vectors.signData.msg, 'hex');
  //  const secretNonce = Buffer.from(vectors.signData.secretNonce, 'hex');
  //  const aggNonce = Buffer.from(vectors.signData.aggNonce, 'hex');
  //  const secretKey = Buffer.from(vectors.signData.secretKey, 'hex');
  //  const { nonSignerKeyIndices } = vectors.signData;
  //  const publicNonce = Buffer.concat([
  //    secp.getPublicKey(secretNonce.slice(0, 32), true),
  //    secp.getPublicKey(secretNonce.slice(32), true),
  //  ]);
  //  const vector = vectors.signVectors.odd;
  //
  //  const publicKeys = nonSignerKeyIndices.map((i) => vectorPublicKeys[i]);
  //  const publicKey = secp.schnorr.getPublicKey(secretKey);
  //  publicKeys.splice(vector.signerIndex, 0, publicKey);
  //  const { keyAggSession } = await musig.keyAgg(publicKeys);
  //
  //  const tweaks = new Array(100).fill(0).map(() => secp.utils.randomBytes());
  //  let xOnly = false;
  //  let i = 0;
  //  await mark('addTweaks', 1000, async () => {
  //    await musig.addTweaks(keyAggSession, tweaks.slice(i, i + 1), [xOnly]);
  //    xOnly = !xOnly;
  //    i = (i + 17) % tweaks.length;
  //  });
  //
  //  const { sig, signingSession } = await musig.partialSign({
  //    msg,
  //    secretKey,
  //    nonce: { secretNonce },
  //    aggNonce,
  //    keyAggSession,
  //  });
  //  await mark('partialSign', 250, async () => {
  //    musig.partialSign({ msg, secretKey, nonce: { secretNonce }, aggNonce, keyAggSession });
  //  });
  //  await mark('partialVerify', 250, async () => {
  //    musig.partialVerify({ sig, msg, publicKey, publicNonce, aggNonce, keyAggSession });
  //  });
  //  await mark('partialVerify w/session', 250, async () => {
  //    musig.partialVerify({
  //      sig,
  //      msg,
  //      publicKey,
  //      publicNonce,
  //      aggNonce,
  //      keyAggSession,
  //      signingSession,
  //    });
  //  });

  console.log();
  logMem();
});
