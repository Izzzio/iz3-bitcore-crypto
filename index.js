/**
 iZ³ | Izzzio blockchain - https://izzz.io

 Copyright 2018 Izio Ltd (OOO "Изио")

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

/**
 * bitcore-lib crypto plugin
 */

const bitcore = require("bitcore-lib");
const Message = require('bitcore-message');
const logger = new (require(global.PATH.mainDir + '/modules/logger'))("bitcore");
/**
 * Validate sign
 * @param data
 * @param sign
 * @param publicKey
 * @return {*|Boolean}
 */
function validate(data, sign, publicKey) {
    publicKey = String(publicKey);
    data = String(data);
    sign = String(sign);
    try {
        return new Message(data).verify(publicKey, sign);
    } catch (e) {
        return false;
    }
}

/**
 * Sign data function
 * @param data
 * @param privateKeyData
 * @return {string}
 */
function sign(data, privateKeyData) {
    privateKeyData = String(privateKeyData);
    data = String(data);

    let privateKey = new bitcore.PrivateKey(privateKeyData);
    let message = new Message(data);

    return message.sign(privateKey).toString();
}

/**
 * Generate wallet from configured credentials
 * @param {object} config
 * @return {{keysPair: {private: {senderContainerName, certificateName}, public: *}}}
 */
function generateWallet(config) {
    let hash = bitcore.crypto.Hash.sha256(Math.random() + Math.random());
    let privateKey = bitcore.crypto.BN.fromBuffer(hash).toString('hex');

    let address = new bitcore.PrivateKey(privateKey).toAddress().toString();

    return {
        keysPair: {
            private: privateKey,
            public: address
        }
    }
}

module.exports = function register(blockchain, config, storj,) {
    logger.info('Initialize...');

    /**
     * @var {Cryptography}
     */
    let crypto = storj.get('cryptography');

    crypto.registerSign('bitcore', validate, sign);

    blockchain.wallet.registerGeneratorHook(function () {
        return generateWallet(config);
    });

    logger.info('OK');
};