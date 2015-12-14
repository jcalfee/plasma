import assert from "assert"
import {createToken} from '@graphene/time-token'
import {Signature, PrivateKey, Aes} from "@graphene/ecc"
import hash from "@graphene/hash"
import FormData from "form-data"
import bs58 from "bs58"
import walletFetch from "../src/fetch"
import WalletSyncServer from "../src/WalletSyncServer"

const host = process.env.npm_package_config_server_host
const port = process.env.npm_package_config_server_port

const server = new WalletSyncServer(host, port)
const private_key = PrivateKey.fromSeed("")
const public_key = private_key.toPublicKey().toString()
const code = createToken(private_key.toPublicKey().toString())
const encrypted_data = Aes.fromSeed("").encrypt("data")
const local_hash = hash.sha256(encrypted_data)
const signature = Signature.signBuffer(encrypted_data, private_key)

/** These test may depend on each other.  For example: createWallet is the setup for walletFetchWallet, etc...  */
describe('Wallet sync client', () => {

    before( done =>{
        // clean up from a failed run
        var p1 = deleteWallet("", "data")
        var p2 = deleteWallet("2", "data2")
        Promise.all([ p1, p2 ])
            .catch( error =>{ if(error.res.statusText !== 'Not Found') {
                console.error(error, error.stack); throw error }})
            .then(()=>{ done() })
    })

    it('createWallet', done => {
        server.createWallet(code, encrypted_data, signature).then( ()=> done() )
            .catch( error =>{ console.error(error, error.stack); throw error })
    })

    it('fetchWallet (Recovery)', done => {
        let local_hash = null // recovery, the local_hash is not known
        server.fetchWallet(public_key, local_hash).then(()=>{ done() })
            .catch( error =>{ console.error(error, error.stack); throw error })
    })
    
    it('fetchWallet (Not Modified)', done => {
        server.fetchWallet(public_key, local_hash)
        .catch( error =>{ if(error.res.statusText !== 'Not Modified') {
            console.error(error, error.stack); throw error }})
        .then(()=>{ done() })
    })
    
    it('saveWallet', done => {
        let original_local_hash = local_hash
        let encrypted_data = Aes.fromSeed("").encrypt("data2")
        let signature = Signature.signBuffer(encrypted_data, private_key)
        server.saveWallet( original_local_hash, encrypted_data, signature ).then( json =>{
            assert.equal(json.local_hash, hash.sha256(encrypted_data, 'base64'), 'local_hash')
            assert(json.updated, 'updated')
            done()
        }).catch( error =>{ console.error(error, error.stack); throw error })
    })
    
    it('saveWallet (Conflict)', done => {
        // original hash will not match
        let original_local_hash = hash.sha256(Aes.fromSeed("").encrypt("Conflict"))
        let encrypted_data = Aes.fromSeed("").encrypt("data2")
        let signature = Signature.signBuffer(encrypted_data, private_key)
        server.saveWallet( original_local_hash, encrypted_data, signature )
            .catch( error =>{ if(error.res.statusText === 'Conflict') done()
                else console.log(error, error.stack) })
    })

    it('saveWallet (Unknown key)', done => {
        // change "nobody" to "" and it should pass (should match createWallet's private key)
        let private_key = PrivateKey.fromSeed("nobody")
        let original_local_hash = hash.sha256(Aes.fromSeed("").encrypt("data2"))
        let encrypted_data = Aes.fromSeed("").encrypt("data2")
        let signature = Signature.signBuffer(encrypted_data, private_key)
        server.saveWallet( original_local_hash, encrypted_data, signature )
            .catch( error =>{ if(error.res.statusText === 'Not Found') done()
                else console.log(error, error.stack) })
    })

    it('changePassword', done => {
        let original_private_key =  PrivateKey.fromSeed("")
        let original_encrypted_data = Aes.fromSeed("").encrypt("data2")
        let original_local_hash = hash.sha256(original_encrypted_data)
        let original_signature = Signature.signBufferSha256(original_local_hash, original_private_key)
        let new_private_key = PrivateKey.fromSeed("2")
        let new_encrypted_data =  Aes.fromSeed("2").encrypt("data2")
        let new_signature = Signature.signBuffer(new_encrypted_data, new_private_key)
        server.changePassword(
            original_local_hash, original_signature, new_encrypted_data, new_signature
        ).then( json => {
            assert.equal(json.local_hash, hash.sha256(new_encrypted_data, 'base64'), 'local_hash')
            assert(json.updated, 'updated')
            done()
        })
        .catch( error =>{ console.error(error); throw error })
    })

    /** End of the wallet tests, clean-up... */
    it('deleteWallet', done=>{
        let private_key = PrivateKey.fromSeed("2")
        let encrypted_data = Aes.fromSeed("2").encrypt("data2")
        let local_hash = hash.sha256(encrypted_data)
        let sig = Signature.signBufferSha256(local_hash, private_key)
        deleteWallet("2", "data2").then(() =>{ done() })
            .catch( error =>{ console.error(error); throw error })
    })

})

function deleteWallet(private_key_seed, wallet_data) {
    let private_key = PrivateKey.fromSeed(private_key_seed)
    let encrypted_data = Aes.fromSeed(private_key_seed).encrypt(wallet_data)
    let local_hash = hash.sha256(encrypted_data)
    let signature = Signature.signBufferSha256(local_hash, private_key)
    return server.deleteWallet( local_hash, signature )
}