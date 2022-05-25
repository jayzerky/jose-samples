const node_jose = require('node-jose');
const jose = require('jose')
const { Certificate } = require('@fidm/x509')
const crypto = require('crypto')

async function decode(data){
    try {
        let jwetokenObj = {}
        let jwetoken = JSON.parse(Buffer.from(data.split('.')[1], 'base64').toString());
        let jwtPayload = node_jose.parse(jwetoken.Payload);
        let protectedHead = jose.decodeProtectedHeader(data);
        jwetokenObj.headers = protectedHead;
        let prefix = '-----BEGIN CERTIFICATE-----\n';
        let postfix = '-----END CERTIFICATE-----';
        let cert = protectedHead.x5c[0];
        let complete_cert = prefix + cert.toString('base64').match(/.{0,64}/g).join('\n') + postfix;
        let x5cCerts = Certificate.fromPEM(complete_cert);

        let jwePubKey = await jose.importSPKI(x5cCerts.publicKey.toPEM());
        let jwePivKey = await Keyvault.checkKeyId('niceapp');
            jwePivKey = crypto.createPrivateKey(jwePivKey);
        let jweVerify = await jose.compactVerify(data, jwePubKey);
        let decryptCK = await jose.compactDecrypt(jwtPayload.input, jwePivKey)

        jwetokenObj["Payload"] = decryptCK.plaintext.toString()
        return jwetokenObj
    } catch (error) {
        console.log(error)
        return error
    }
}

async function encode(unique_id, data){
    let cmfData = data;
    let protectedHead = ''
    let x5c_object = [];

    try {
        let server_privkey = await Keyvault.checkKeyId('newapp');
        server_privkey = crypto.createPrivateKey(server_privkey);

        let server_cert = await Keyvault.checkCertId('newapp');
        server_cert = server_cert.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE', '').replace('\n', '')

        let interca_cert = await KeyVault.checkCertId('interca');
        interca_cert = interca_cert.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE', '').replace('\n', '')

        if(server_privkey.assymetricKeyType == 'ec'){
            protectedHead = { "alg": "ES256", "kid": unique_id, "x5c": x5c_object}
        }else{
            protectedHead = { "alg": "PS256", "kid": unique_id, "x5c": x5c_object}
        }

        x5c_object.push(server_cert)
        x5c_object.push(interca_cert)
        cmfData = JSON.stringify(cmfData);

        const jws = await jose.CompactSign( new TextEncoder().encode(cmfData))
                                .setProtectedHeader(protectedHead)
                                .sign(server_privkey)
        
        return jws
                            
    } catch (error) {
        console.log(error)
        return error
    }
}