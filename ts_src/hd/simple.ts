import { Keyring, SerializedSimpleKey, ToSignInput } from "./types";
import { ZERO_KEY, ZERO_PRIVKEY } from "./common";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { BaseWallet } from "./base";
import * as tinysecp from "bells-secp256k1";
import ECPairFactory, { ECPairInterface } from "belpair";
import { Psbt } from "belcoinjs-lib";
import { sha256 } from "@noble/hashes/sha256";

const ECPair = ECPairFactory(tinysecp);

class HDSimpleKey extends BaseWallet implements Keyring<SerializedSimpleKey> {
  privateKey: Uint8Array = ZERO_PRIVKEY;
  publicKey = ZERO_KEY;

  private pair?: ECPairInterface;

  constructor(privateKey: Uint8Array) {
    super();

    this.privateKey = privateKey;
  }

  private initPair() {
    if (!this.privateKey)
      throw new Error("Simple Keyring: Invalid privateKey provided");
    if (!this.pair) {
      this.pair = ECPair.fromPrivateKey(Buffer.from(this.privateKey));
      this.publicKey = this.pair.publicKey;
    }
  }

  signTypedData(address: string, typedData: Record<string, unknown>) {
    this.initPair();

    return this.signMessage(address, JSON.stringify(typedData));
  }

  verifyMessage(_address: string, text: string, sig: string) {
    this.initPair();

    return this.pair!.verify(
      Buffer.from(hexToBytes(text)),
      Buffer.from(hexToBytes(sig))
    )!;
  }

  getAccounts() {
    this.initPair();

    return [this.getAddress(this.publicKey)!];
  }

  serialize() {
    this.initPair();

    const wif = this.pair?.toWIF();
    if (!wif) throw new Error("Failed to export wif for simple wallet");

    return {
      privateKey: wif,
      addressType: this.addressType!,
    };
  }

  deserialize(state: SerializedSimpleKey) {
    const wallet = HDSimpleKey.deserialize(state);
    this.privateKey = wallet.privateKey;
    this.pair = wallet.pair;
    this.addressType = wallet.addressType;
    return this;
  }

  static deserialize(state: SerializedSimpleKey) {
    const pair = ECPair.fromWIF(state.privateKey);
    const wallet = new this(pair.privateKey!);
    wallet.initPair();
    wallet.addressType = state.addressType;
    return wallet;
  }

  exportAccount(
    _address: string,
    _options?: Record<string, unknown> | undefined
  ) {
    this.initPair();

    return this.pair!.toWIF();
  }

  exportPublicKey(_address: string) {
    this.initPair();

    return bytesToHex(this.publicKey);
  }

  signPsbt(psbt: Psbt, inputs: ToSignInput[]) {
    this.initPair();

    for (let i of inputs) {
      psbt.signInput(i.index, this.pair!, i.sighashTypes);
    }
    psbt.finalizeAllInputs();
  }

  signMessage(_address: string, message: string) {
    this.initPair();

    const encoded = sha256(message);
    return bytesToHex(this.pair!.sign(Buffer.from(encoded)));
  }

  signPersonalMessage(address: string, message: string) {
    return this.signMessage(address, message);
  }
}

export default HDSimpleKey;
