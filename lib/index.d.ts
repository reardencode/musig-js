/*! musig-js - MIT License (c) 2022 Brandon Black */
import { Point } from '@noble/secp256k1';
declare type Hex = Uint8Array | string;
declare type PrivKey = Hex | bigint | number;
declare type PubKey = Hex | Point;
declare type MusigPrivateNonce = Hex | [PrivKey, PrivKey];
declare type MusigPublicNonce = Hex | [PubKey, PubKey];
interface MusigNonce {
    privateNonce: MusigPrivateNonce;
    publicNonce?: MusigPublicNonce;
}
export declare type MusigPublicKey = {
    parity: 0 | 1;
    publicKey: Uint8Array;
    keyAggCache: string;
};
export interface MusigPartialSig {
    sig: PrivKey;
    session: Hex;
}
export declare function nonceAgg(nonces: MusigPublicNonce[]): Uint8Array;
export declare function keyAgg(publicKeys: PubKey[], opts?: {
    tweaks?: PrivKey[];
    tweaksXOnly?: boolean[];
    sort?: boolean;
}): Promise<MusigPublicKey>;
export declare function keyAggSync(publicKeys: PubKey[], opts?: {
    tweaks?: PrivKey[];
    tweaksXOnly?: boolean[];
    sort?: boolean;
}): MusigPublicKey;
export declare function addTweaks(keyAggCache: Hex, tweaks: PrivKey[], tweaksXOnly?: boolean[]): MusigPublicKey;
export declare function nonceGen(sessionId?: Hex, privateKey?: PrivKey, message?: Hex, aggregatePublicKey?: PubKey, extraInput?: Hex): Promise<{
    privateNonce: Uint8Array;
    publicNonce: Uint8Array;
}>;
export declare function nonceGenSync(sessionId?: Hex, privateKey?: PrivKey, message?: Hex, aggregatePublicKey?: PubKey, extraInput?: Hex): {
    privateNonce: Uint8Array;
    publicNonce: Uint8Array;
};
export declare function partialSign(message: Hex, privKey: PrivKey, nonce: MusigNonce, aggNonce: MusigPublicNonce, keyAggCache: Hex): Promise<{
    sig: Uint8Array;
    session: string;
}>;
export declare function partialSignSync(message: Hex, privKey: PrivKey, nonce: MusigNonce, aggNonce: MusigPublicNonce, keyAggCache: Hex): {
    sig: Uint8Array;
    session: string;
};
export declare function partialVerify(sig: PrivKey, message: Hex, publicKey: PubKey, publicNonce: MusigPublicNonce, aggNonce: MusigPublicNonce, keyAggCache: Hex, session?: Hex): Promise<false | {
    session: string;
}>;
export declare function partialVerifySync(sig: PrivKey, message: Hex, publicKey: PubKey, publicNonce: MusigPublicNonce, aggNonce: MusigPublicNonce, keyAggCache: Hex, session?: Hex): false | {
    session: string;
};
export declare function signAgg(sigs: PrivKey[], session: Hex): Uint8Array;
export {};
