/*! musig-js - MIT License (c) 2022 Brandon Black */
interface MuSig {
    keyAgg(publicKeys: Uint8Array[], opts?: {
        tweaks?: Uint8Array[];
        tweaksXOnly?: boolean[];
        sort?: boolean;
    }): AggregatePublicKey;
    addTweaks(session: KeyAggSession, tweaks: Uint8Array[], tweaksXOnly?: boolean[]): AggregatePublicKey;
    nonceGen({ sessionId, secretKey, message, aggregatePublicKey, extraInput, }: {
        sessionId: Uint8Array;
        secretKey?: Uint8Array;
        message?: Uint8Array;
        aggregatePublicKey?: Uint8Array;
        extraInput?: Uint8Array;
    }): {
        secretNonce: Uint8Array;
        publicNonce: Uint8Array;
    };
    nonceAgg(nonces: Uint8Array[]): Uint8Array;
    partialSign({ message, secretKey, nonce, aggNonce, session, }: {
        message: Uint8Array;
        secretKey: Uint8Array;
        nonce: Nonce;
        aggNonce: Uint8Array;
        session: KeyAggSession;
    }): {
        sig: Uint8Array;
        session: Uint8Array;
    };
    partialVerify({ sig, message, publicKey, publicNonce, aggNonce, keyAggSession, session, }: {
        sig: Uint8Array;
        message: Uint8Array;
        publicKey: Uint8Array;
        publicNonce: Uint8Array;
        aggNonce: Uint8Array;
        keyAggSession: KeyAggSession;
        session?: Uint8Array;
    }): false | {
        session: Uint8Array;
    };
    signAgg(sigs: Uint8Array[], session: Uint8Array): Uint8Array;
}
interface Crypto {
    pointAddTweak(p: Uint8Array, t: Uint8Array, compressed: boolean): Uint8Array | null;
    pointAdd(a: Uint8Array, b: Uint8Array, compressed: boolean): Uint8Array | null;
    pointMultiply(p: Uint8Array, a: Uint8Array, compressed: boolean): Uint8Array | null;
    pointNegate(p: Uint8Array): Uint8Array;
    pointCompress(p: Uint8Array, compressed: boolean): Uint8Array;
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
    session: KeyAggSession;
}
export interface MuSigPartialSig {
    sig: Uint8Array;
    session: Uint8Array;
}
export declare function MuSigFactory(ecc: Crypto): MuSig;
export {};
