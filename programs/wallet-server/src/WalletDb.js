import crypto from "crypto";
import hash from "@graphene/hash";
import {Wallet} from "./db/models.js";
import {Signature} from "@graphene/ecc";

/**
    @arg {string} encrypted_data - binary
    @arg {string} signature - binary
*/
export function createWallet(encrypted_data, signature, email_sha1) {
    encrypted_data = new Buffer(encrypted_data, "binary");
    const signature_buffer = new Buffer(signature, "binary");
    const sig = Signature.fromBuffer(signature_buffer);
    const lh = hash.sha256(encrypted_data);
    const pub = sig.recoverPublicKey(lh);
    if (!sig.verifyHash(lh, pub))
        return Promise.reject("signature_verify");

    const public_key = pub.toString();
    const local_hash = lh.toString("base64");
    email_sha1 = new Buffer(email_sha1, "binary").toString("base64");
    return Wallet.create({
        public_key, email_sha1, encrypted_data,
        signature: signature_buffer.toString("base64"), local_hash })
        // return only select fields from the wallet....
        // Do not return wallet.id, db sequences may change.
        .then(wallet => { return { local_hash, created: wallet.createdAt }; });
}

/**
    @arg {Buffer} encrypted_data - binary
    @arg {string} signature - binary
*/
export function saveWallet(original_local_hash, encrypted_data, signature) {
    original_local_hash = new Buffer(original_local_hash, "binary");
    encrypted_data = new Buffer(encrypted_data, "binary");
    const sig = Signature.fromBuffer(new Buffer(signature, "binary"));
    const lh = hash.sha256(encrypted_data);
    const pub = sig.recoverPublicKey(lh);
    if (!sig.verifyHash(lh, pub)) {
        return Promise.reject("signature_verify");
    }

    const public_key = pub.toString();
    const local_hash = lh.toString("base64");
    return Wallet.findOne({where: {public_key}}).then(wallet => {
        if (!wallet) return "Not Found";
        if (wallet.local_hash !== original_local_hash.toString("base64")) return "Conflict";
        wallet.encrypted_data = encrypted_data;
        wallet.local_hash = local_hash;
        return wallet.save().then(wallet => {
            return { local_hash, updated: wallet.updatedAt };
        });
    });
}

export function changePassword({ original_local_hash, original_signature,
    new_encrypted_data, new_signature }) {
    new_encrypted_data = new Buffer(new_encrypted_data, "binary");
    let original_pubkey;
    {
        const sig = Signature.fromBuffer(new Buffer(original_signature, "binary"));
        const local_hash = new Buffer(original_local_hash, "binary");
        const public_key = sig.recoverPublicKey(local_hash);
        if (!sig.verifyHash(local_hash, public_key))
            return Promise.reject("signature_verify (original)");
        original_pubkey = public_key.toString();
    }
    let new_local_hash, new_pubkey;
    {
        const sig = Signature.fromBuffer(new Buffer(new_signature, "binary"));
        const local_hash = hash.sha256(new_encrypted_data);
        const public_key = sig.recoverPublicKey(local_hash);
        if (!sig.verifyHash(local_hash, public_key))
            return Promise.reject("signature_verify (new)");
        new_local_hash = local_hash.toString("base64");
        new_pubkey = public_key.toString();
    }
    return Wallet.findOne({where: {public_key: original_pubkey}}).then(wallet => {
        if (!wallet) return "Not Found";
        wallet.encrypted_data = new_encrypted_data;
        wallet.local_hash = new_local_hash;
        wallet.public_key = new_pubkey;
        return wallet.save().then(wallet1 => {
            return { local_hash: new_local_hash, updated: wallet1.updatedAt };
        });
    });
}

export function deleteWallet({ local_hash, signature }) {
    local_hash = new Buffer(local_hash, "binary");
    signature = new Buffer(signature, "binary");
    const sig = Signature.fromBuffer(signature);
    const public_key = sig.recoverPublicKey(local_hash);
    if (!sig.verifyHash(local_hash, public_key))
        return Promise.reject("signature_verify");
    return Wallet.findOne({where: {public_key: public_key.toString()}}).then(wallet => {
        if (!wallet) return "Not Found";
        return wallet.destroy().then(() => "OK");
    });
}
