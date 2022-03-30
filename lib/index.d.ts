/*! musig-js - MIT License (c) 2022 Brandon Black */
export interface MuSig {
    keyAgg(publicKeys: Uint8Array[], opts?: {
        tweaks?: Uint8Array[];
        tweaksXOnly?: boolean[];
        sort?: boolean;
    }): AggregatePublicKey;
    addTweaks(keyAggSession: KeyAggSession, tweaks: Uint8Array[], tweaksXOnly?: boolean[]): AggregatePublicKey;
    nonceGen({ sessionId, secretKey, msg, publicKey, extraInput, }: {
        sessionId: Uint8Array;
        secretKey?: Uint8Array;
        msg?: Uint8Array;
        publicKey?: Uint8Array;
        extraInput?: Uint8Array;
    }): {
        secretNonce: Uint8Array;
        publicNonce: Uint8Array;
    };
    nonceAgg(nonces: Uint8Array[]): Uint8Array;
    createSigningSession(aggNonce: Uint8Array, msg: Uint8Array, keyAggSession: KeyAggSession): Uint8Array;
    partialSign({ msg, secretKey, nonce, aggNonce, keyAggSession, signingSession, verify, }: {
        msg: Uint8Array;
        secretKey: Uint8Array;
        nonce: Nonce;
        aggNonce: Uint8Array;
        keyAggSession: KeyAggSession;
        signingSession?: Uint8Array;
        verify?: boolean;
    }): MuSigPartialSig;
    partialVerify({ sig, msg, publicKey, publicNonce, aggNonce, keyAggSession, signingSession, }: {
        sig: Uint8Array;
        msg: Uint8Array;
        publicKey: Uint8Array;
        publicNonce: Uint8Array;
        aggNonce: Uint8Array;
        keyAggSession: KeyAggSession;
        signingSession?: Uint8Array;
    }): false | MuSigPartialSig;
    signAgg(sigs: Uint8Array[], signingSession: Uint8Array): Uint8Array;
}
export interface Crypto {
    pointAddTweak(p: Uint8Array, t: Uint8Array, compressed: boolean): Uint8Array | null;
    pointAdd(a: Uint8Array, b: Uint8Array, compressed: boolean): Uint8Array | null;
    pointMultiplyUnsafe(p: Uint8Array, a: Uint8Array, compressed: boolean): Uint8Array | null;
    pointMultiplyAndAddUnsafe(p1: Uint8Array, a: Uint8Array, p2: Uint8Array, compressed: boolean): Uint8Array | null;
    pointNegate(p: Uint8Array): Uint8Array;
    pointCompress(p: Uint8Array): Uint8Array;
    secretAdd(a: Uint8Array, b: Uint8Array): Uint8Array;
    secretMultiply(a: Uint8Array, b: Uint8Array): Uint8Array;
    secretNegate(a: Uint8Array): Uint8Array;
    secretMod(a: Uint8Array): Uint8Array;
    isSecret(s: Uint8Array): boolean;
    isPoint(p: Uint8Array): boolean;
    isXOnlyPoint(p: Uint8Array): boolean;
    liftX(p: Uint8Array): Uint8Array | null;
    pointX(p: Uint8Array): Uint8Array;
    hasEvenY(p: Uint8Array): boolean;
    getPublicKey(s: Uint8Array, compressed: boolean): Uint8Array | null;
    taggedHash(tag: string, ...messages: Uint8Array[]): Uint8Array;
    sha256(...messages: Uint8Array[]): Uint8Array;
}
export interface Nonce {
    secretNonce: Uint8Array;
    publicNonce?: Uint8Array;
}
export interface KeyAggSession {
    base: Uint8Array;
    rest: Uint8Array;
}
export interface AggregatePublicKey {
    parity: 0 | 1;
    publicKey: Uint8Array;
    keyAggSession: KeyAggSession;
}
export interface MuSigPartialSig {
    sig: Uint8Array;
    signingSession: Uint8Array;
}
export declare function MuSigFactory(ecc: Crypto): MuSig;
