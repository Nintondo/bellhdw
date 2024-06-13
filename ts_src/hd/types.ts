import { Network, Psbt } from "belcoinjs-lib";

export type Base58String = string;

export interface PrivateKeyOptions {
  seed: string;
  hdPath?: string;
}

export interface FromSeedOpts {
  seed: Uint8Array;
  hideRoot?: boolean;
  addressType?: AddressType;
  hdPath?: string;
  network?: Network;
}

export interface FromMnemonicOpts {
  mnemonic: string;
  passphrase?: string;
  hideRoot?: boolean;
  addressType?: AddressType;
  hdPath?: string;
}

export interface PublicKeyOptions
  extends Omit<PrivateKeyOptions, "privateKey"> {
  xkey: Base58String;
  publicKey: Uint8Array;
}

interface SerializedBase {
  addressType: AddressType;
  network?: Network;
}

export interface SerializedHDKey extends SerializedBase {
  seed: string;
  numberOfAccounts?: number;
  hideRoot?: boolean;
  hdPath?: string;
}

export interface SerializedSimpleKey extends SerializedBase {
  privateKey: string;
  isHex?: boolean;
}

export type Hex = string;

export interface ToSignInput {
  index: number;
  publicKey: string;
  sighashTypes?: number[];
}

export enum AddressType {
  P2PKH,
  P2WPKH,
  P2TR,
  P2SH_P2WPKH,
  M44_P2WPKH,
  M44_P2TR,
}

export type Keyring<State> = {
  addressType?: AddressType;
  hideRoot?: boolean;
  generate?: (seed: Uint8Array, entropy: Uint8Array) => Keyring<State>;

  getAccounts(): Hex[];
  toggleHideRoot?(): void;
  addAccounts?(number: number): string[];
  serialize(): State;
  deserialize(state: State): Keyring<State>;
  exportAccount(address: Hex, options?: Record<string, unknown>): string;
  exportPublicKey(address: Hex): string;
  verifyMessage(address: Hex, text: string, sig: string): boolean;
  signPsbt(psbt: Psbt, inputs: ToSignInput[]): void;
  signMessage(address: Hex, message: Hex): string;
  signPersonalMessage(address: Hex, message: Hex): string;
  signTypedData(address: Hex, typedData: Record<string, unknown>): string;
  signAllInputsInPsbt(
    psbt: Psbt,
    accountAddress: string
  ): { signatures: (string | undefined)[] };
  signInputsWithoutFinalizing(
    psbt: Psbt,
    inputs: ToSignInput[]
  ): {
    inputIndex: number;
    partialSig: { pubkey: Buffer; signature: Buffer }[];
  }[];
  setNetwork(network: Network): void;
};

export const DISALLOWED_CHILD_METHODS: (keyof Keyring<any>)[] = [
  "deserialize",
  "serialize",
  "getAccounts",
  "generate",
];
