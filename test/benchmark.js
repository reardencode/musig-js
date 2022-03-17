const { run, mark, logMem } = require('micro-bmark');
const musig = require('..');
const secp = require('@noble/secp256k1');
const { join } = require('path');
const { hmac } = require('@noble/hashes/hmac');
const { sha256 } = require('@noble/hashes/sha256');
const vectors = require('./vectors.json');

secp.utils.hmacSha256Sync = (key, ...msgs) => {
  const h = hmac.create(sha256, key);
  msgs.forEach((msg) => h.update(msg));
  return h.digest();
};

secp.utils.sha256Sync = (...msgs) => {
  const h = sha256.create();
  msgs.forEach((msg) => h.update(msg));
  return h.digest();
};

// run([4, 8, 16], async (windowSize) => {
run(async (windowSize) => {
  const samples = 1000;
  //console.log(`-------\nBenchmarking window=${windowSize} samples=${samples}...`);
  await mark(() => {
    secp.utils.precompute(windowSize);
  });

  logMem();
  console.log();

  await mark('keyAgg(2)', 500, async () => {
    return musig.keyAgg(vectors.publicKeys.slice(1));
  });
  await mark('keyAgg(3)', 400, async () => {
    return musig.keyAgg(vectors.publicKeys);
  });
  await mark('keyAgg(5)', 250, async () => {
    return musig.keyAgg(vectors.publicKeys.concat(vectors.publicKeys.slice(1)));
  });

  const { msg, privateNonce, aggNonce, signingKey, nonSignerKeyIndices } = vectors.signData;
  const publicNonce =
    secp.utils.bytesToHex(secp.getPublicKey(privateNonce.slice(0, 64), true)) +
    secp.utils.bytesToHex(secp.getPublicKey(privateNonce.slice(64), true));
  const vector = vectors.signVectors.odd;

  const publicKeys = nonSignerKeyIndices.map((i) => vectors.publicKeys[i]);
  const signingPublicKey = secp.utils.bytesToHex(secp.schnorr.getPublicKey(signingKey));
  publicKeys.splice(vector.signerIndex, 0, signingPublicKey);
  const { keyAggCache } = await musig.keyAgg(vectors.publicKeys);

  const tweaks = new Array(100).fill(0).map(() => secp.utils.randomBytes());
  let xOnly = false;
  let i = 0;
  await mark('addTweaks', 1000, async () => {
    await musig.addTweaks(keyAggCache, tweaks.slice(i, i + 1), [xOnly]);
    xOnly = !xOnly;
    i = (i + 17) % tweaks.length;
  });

  const { sig, session } = await musig.partialSign(
    msg,
    signingKey,
    { privateNonce },
    aggNonce,
    keyAggCache
  );
  await mark('partialSign', 250, async () => {
    musig.partialSign(msg, signingKey, { privateNonce }, aggNonce, keyAggCache);
  });
  await mark('partialVerify', 250, async () => {
    musig.partialVerify(sig, msg, signingPublicKey, publicNonce, aggNonce, keyAggCache);
  });
  await mark('partialVerify w/session', 250, async () => {
    musig.partialVerify(sig, msg, signingPublicKey, publicNonce, aggNonce, keyAggCache, session);
  });

  console.log();
  logMem();
});
