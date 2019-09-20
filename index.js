/**
 iZ³ | Izzzio blockchain - https://izzz.io

 Copyright 2018 Izio LLC (OOO "Изио")

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

const ADDRESS_PREFIX = 'iz';

/**
 * Public key 2 address
 * @param pub
 * @return {*}
 */
function public2address(pub) {
    pub = pub.substr(1);
    pub = ADDRESS_PREFIX + pub;

    return pub;
}

/**
 * Address 2 public key
 * @param add
 * @return {string}
 */
function address2pubic(add) {
    if(add.indexOf(ADDRESS_PREFIX) !== 0) {
        throw new Error('Invalid address');
    }

    return '1' + add.substr(ADDRESS_PREFIX.length);
}

/**
 * Validate sign
 * @param data
 * @param sign
 * @param publicKey
 * @return {*|Boolean}
 */
function validate(data, sign, publicKey) {
    publicKey = address2pubic(String(publicKey));
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
    let hash = bitcore.crypto.Hash.sha256(Buffer.from(String(Math.random()) + String(Math.random()) + String(Math.random())));
    let privateKey = bitcore.crypto.BN.fromBuffer(hash).toString('hex');

    let address = new bitcore.PrivateKey(privateKey).toAddress().toString();

    return {
        keysPair: {
            private: privateKey,
            public: public2address(address)
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