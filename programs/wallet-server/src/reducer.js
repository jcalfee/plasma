import { checkToken, expire_min } from "@graphene/time-token";
import emailToken from "./EmailToken";
import * as WalletDb from "./WalletDb";
import { Wallet } from "./db/models.js";
import hash from "@graphene/hash";

const console_error = (...message) => { console.error("ERROR reducer", ...message); };

export default function reducer(state, action) {
    if (/redux/.test(action.type)) return state;
    // console_error("reducer\t", action.type)
    const reply = action.reply;
    try {
        switch (action.type) {
        case "requestCode":
            const { email } = action;
            // Embed the sha1 of the email, this is required to limit 1 wallet per email
            const p = emailToken(email, hash.sha1(email.trim().toLowerCase(), "binary"));
            p.on("close", (code, signal) => {
                if (code === 0) {
                    reply("OK", { expire_min: expire_min() });
                    return;
                }
                console_error("emailToken\tcode, signal, email", code, signal, email);
                reply("Internal Server Error", { code });
            });
            break;
        case "createWallet":
            const { code, encrypted_data, signature } = action;
            const result = checkToken(code);
            if (!result.valid) {
                reply("Unauthorized", { message: result.error });
                break;
            }
            const email_sha1 = result.seed;
            reply(WalletDb.createWallet(encrypted_data, signature, email_sha1));
            break;
        case "fetchWallet":
            const public_key = action.public_key;
            const local_hash = action.local_hash ? new Buffer(local_hash, "binary").toString("base64") : "";
            const r = Wallet
                .findOne({ where: { public_key, local_hash: { $ne: local_hash } } })
                .then(wallet => {
                    if (!wallet) return "Not Modified";
                    return {
                        encrypted_data: wallet.encrypted_data.toString("base64"),
                        created: wallet.createdAt, updated: wallet.updatedAt
                    };
                });
            reply(r);
            break;
        case "saveWallet":
            reply(WalletDb.saveWallet(action.original_local_hash, action.encrypted_data, action.signature));
            break;
        case "changePassword":
            reply(WalletDb.changePassword(action));
            break;
        case "deleteWallet":
            reply(WalletDb.deleteWallet(action));
            break;
        default:
            reply("Not Implemented");
        }
    } catch (error) {
        console_error("ERROR", action.type, error, error.stack);
        reply.badRequest(error);
    }
    return state;
}
