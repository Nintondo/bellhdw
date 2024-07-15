import {
  AddressType,
  Keyring,
  SerializedSimpleKey,
  ToSignInput,
} from "./types";
import { ZERO_KEY, ZERO_PRIVKEY } from "./common";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { BaseWallet } from "./base";
import * as tinysecp from "bells-secp256k1";
import ECPairFactory, { ECPairInterface } from "belpair";
import { Network, networks, Psbt, Signer } from "belcoinjs-lib";
import { sha256 } from "@noble/hashes/sha256";
import { crypto as belCrypto } from "belcoinjs-lib";
import { toXOnly } from "../utils/util";

const ECPair = ECPairFactory(tinysecp);

function tapTweakHash(pubKey: Buffer, h: Buffer | undefined): Buffer {
  return belCrypto.taggedHash(
    "TapTweak",
    Buffer.concat(h ? [pubKey, h] : [pubKey])
  );
}

function tweakSigner(
  signer: Signer,
  opts: { network: Network; tweakHash?: Buffer }
): Signer {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  let privateKey: Uint8Array | undefined = signer.privateKey!;
  if (!privateKey) {
    throw new Error("Private key is required for tweaking signer!");
  }
  if (signer.publicKey[0] === 3) {
    privateKey = tinysecp.privateNegate(privateKey);
  }

  const tweakedPrivateKey = tinysecp.privateAdd(
    privateKey,
    tapTweakHash(toXOnly(signer.publicKey), opts.tweakHash)
  );
  if (!tweakedPrivateKey) {
    throw new Error("Invalid tweaked private key!");
  }

  return ECPair.fromPrivateKey(Buffer.from(tweakedPrivateKey), {
    network: opts.network,
  });
}

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
    this.network = state.network;
    return this;
  }

  static deserialize(state: SerializedSimpleKey) {
    let pair: ECPairInterface | undefined;

    if (state.isHex) {
      pair = ECPair.fromPrivateKey(Buffer.from(state.privateKey, "hex"));
    } else {
      pair = ECPair.fromWIF(state.privateKey);
    }

    const wallet = new this(pair.privateKey!);
    wallet.network = state.network;
    wallet.addressType = state.addressType;
    wallet.initPair();
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

    inputs.forEach((input) => {
      const account = this.pair!;
      if (this.addressType === AddressType.P2TR) {
        const signer = tweakSigner(account, {
          network: this.network ?? networks.bellcoin,
        });
        psbt.signInput(input.index, signer, input.sighashTypes);
      } else {
        const signer = account;
        psbt.signInput(input.index, signer, input.sighashTypes);
      }
    });
    psbt.finalizeAllInputs();
  }

  signAllInputsInPsbt(psbt: Psbt, accountAddress: string) {
    this.initPair();
    if (this.pair === undefined)
      throw new Error("Cannot sign all inputs since pair is undefined");
    if (accountAddress !== this.getAddress(this.publicKey))
      throw new Error(
        "Provided account address does not match the wallet's address"
      );

    psbt.data.inputs.forEach((input, idx) => {
      if (this.addressType === AddressType.P2TR) {
        const signer = tweakSigner(this.pair!, {
          network: this.network ?? networks.bellcoin,
        });
        psbt.signInput(
          idx,
          signer,
          input.sighashType !== undefined ? [input.sighashType] : undefined
        );
      } else {
        psbt.signInput(
          idx,
          this.pair!,
          input.sighashType !== undefined ? [input.sighashType] : undefined
        );
      }
    });

    return {
      signatures: psbt.data.inputs.map((i) => {
        if (
          i.partialSig &&
          i.partialSig[0] &&
          i.partialSig[0].signature.length
        ) {
          return i.partialSig[0].signature.toString("hex");
        }
      }),
    };
  }

  signInputsWithoutFinalizing(
    psbt: Psbt,
    inputs: ToSignInput[]
  ): {
    inputIndex: number;
    partialSig: { pubkey: Buffer; signature: Buffer }[];
  }[] {
    this.initPair();
    if (this.pair === undefined)
      throw new Error("Cannot sign inputs since pair is undefined");
    inputs.forEach((input) => {
      if (this.addressType === AddressType.P2TR) {
        const signer = tweakSigner(this.pair!, {
          network: this.network ?? networks.bellcoin,
        });
        psbt.signInput(input.index, signer, input.sighashTypes);
      } else {
        const signer = this.pair!;
        psbt.signInput(input.index, signer, input.sighashTypes);
      }
    });
    return psbt.data.inputs.map((f, i) => ({
      inputIndex: i,
      partialSig: f.partialSig?.flatMap((p) => p) ?? [],
    }));
  }

  signMessage(_address: string, message: string) {
    this.initPair();

    const encoded = sha256(message);
    return this.pair!.sign(Buffer.from(encoded)).toString("base64");
  }

  signPersonalMessage(address: string, message: string) {
    return this.signMessage(address, message);
  }
}

export default HDSimpleKey;
