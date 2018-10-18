/**
 * [generator.js]
 *
 * @version 1.0.0
 * @author Jason L
 * @copyright L, Jason(2018)
 * @license MIT
 */

/*

/*
    MIT LICENSE
    Copyright 2018 Jason L

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.

 */

function makeCustomUatSgQr(payloadFormatIndicator_00_m,
                           pointOfInitiationMethod_01_o,
                           mid, tid, version, qrIssuerUen, qrTimestamp, txnAmtModifier, qrType, secretString,
                           sgQrIdInfo_51_m,
                           merchantCategoryCode_52_m,
                           txnCurrency_53_m,
                           txnAmt_54_c,
                           tipIndicator_55_o,
                           tipAmtFixed_56_c,
                           tipAmtPercent_57_c,
                           countryCode_58_m,
                           merchantName_59_m,
                           merchantCity_60_m,
                           postalCode_61_o,
                           billReference_subfieldOf62_o,
                           mobileNo_subfieldOf62_o,
                           storeLabel_subfieldOf62_o,
                           loyaltyNo_subfieldOf62_o,
                           reference_subfieldOf62_o,
                           customerLabel_subfieldOf62_o,
                           terminalLabel_subfieldOf62_o,
                           txnPurpose_subfieldOf62_o,
                           addnCustDataReq_subfieldOf62_o) {

    let UNKNOWN = "UNKNOWN";

    let rec00 = "";
    let rec01 = "";
    let rec26 = "";
    let rec51 = "";
    let rec52 = "";
    let rec53 = "";
    let rec54 = "";
    let rec55 = "";
    let rec56 = "";
    let rec57 = "";
    let rec58 = "";
    let rec59 = "";
    let rec60 = "";
    let rec61 = "";
    let rec62 = "";
    let rec63 = "";

    if (!payloadFormatIndicator_00_m) {
        payloadFormatIndicator_00_m = "01"
    }
    rec00 = makeCheckedSgQrObj(0, payloadFormatIndicator_00_m);

    rec01 = makeCheckedSgQrObj(1, pointOfInitiationMethod_01_o);

    rec26 = makeNetsMerchantSgQrObject2(mid, tid, version, qrIssuerUen, qrTimestamp, txnAmtModifier, qrType, secretString);

    if (!sgQrIdInfo_51_m) {
        sgQrIdInfo_51_m = UNKNOWN;
    }
    rec51 = makeCheckedSgQrObj(51, sgQrIdInfo_51_m);
    if (!merchantCategoryCode_52_m) {
        merchantCategoryCode_52_m = UNKNOWN;
    }
    rec52 = makeCheckedSgQrObj(52, merchantCategoryCode_52_m);

    if (!txnCurrency_53_m) {
        txnCurrency_53_m = "UNK";
    }
    rec53 = makeCheckedSgQrObj(53, txnCurrency_53_m);

    rec54 = makeCheckedSgQrObj(54, txnAmt_54_c);
    rec55 = makeCheckedSgQrObj(55, tipIndicator_55_o);
    rec56 = makeCheckedSgQrObj(56, tipAmtFixed_56_c);
    rec57 = makeCheckedSgQrObj(57, tipAmtPercent_57_c);

    if (!countryCode_58_m) {
        countryCode_58_m = "UN";
    }
    rec58 = makeCheckedSgQrObj(58, countryCode_58_m);

    if (!merchantName_59_m) {
        merchantName_59_m = UNKNOWN;
    }
    rec59 = makeCheckedSgQrObj(59, merchantName_59_m);

    if (!merchantCity_60_m) {
        merchantCity_60_m = UNKNOWN;
    }
    rec60 = makeCheckedSgQrObj(60, merchantCity_60_m);
    rec61 = makeCheckedSgQrObj(61, postalCode_61_o);

    let addDataData = "";
    if (billReference_subfieldOf62_o) {
        addDataData += makeCheckedSgQrObj(1, billReference_subfieldOf62_o);
    }
    if (mobileNo_subfieldOf62_o) {
        addDataData += makeCheckedSgQrObj(2, mobileNo_subfieldOf62_o);
    }
    if (storeLabel_subfieldOf62_o) {
        addDataData += makeCheckedSgQrObj(3, storeLabel_subfieldOf62_o);
    }
    if (loyaltyNo_subfieldOf62_o) {
        addDataData += makeCheckedSgQrObj(4, loyaltyNo_subfieldOf62_o);
    }
    if (reference_subfieldOf62_o) {
        addDataData += makeCheckedSgQrObj(5, reference_subfieldOf62_o);
    }
    if (customerLabel_subfieldOf62_o) {
        addDataData += makeCheckedSgQrObj(6, customerLabel_subfieldOf62_o);
    }
    if (terminalLabel_subfieldOf62_o) {
        addDataData += makeCheckedSgQrObj(7, terminalLabel_subfieldOf62_o);
    }
    if (txnPurpose_subfieldOf62_o) {
        addDataData += makeCheckedSgQrObj(8, txnPurpose_subfieldOf62_o);
    }
    if (addnCustDataReq_subfieldOf62_o) {
        addDataData += makeCheckedSgQrObj(9, addnCustDataReq_subfieldOf62_o);
    }

    rec62 = makeCheckedSgQrObj(62, addDataData);
    let preCrc = rec00 + rec01 + rec26 + rec51 + rec52 + rec53 + rec54 + rec55 + rec56 + rec57 + rec58 + rec59 + rec60 + rec61 + rec62 + "6304";
    let crc = crc16(preCrc);
    let crcAsHex = Number(crc).toString(16);
    if (crcAsHex.length < 4) {
        let lengthDiff = 4 - crcAsHex.length;
        crcAsHex = "0000".substring(0, lengthDiff) + crcAsHex;
    }

    return preCrc + crcAsHex.toUpperCase();
}

function makeCheckedSgQrObj(id, data) {
    if (id === null || id < 0 || id > 99 || !data) {
        return "";
    }
    let idString = "" + id;
    if (id < 10) {
        idString = "0" + id;
    }
    let dataLen;
    if (data.length > 99) {
        data = data.substring(0, 99);
        dataLen = "99";
    } else if (data.length < 10) {
        dataLen = "0" + data.length;
    } else {
        dataLen = data.length;
    }
    return idString + dataLen + data;
}

function makeNetsMerchantSgQrObject2(mid, tid, version, qrIssuerUen, qrTimestamp, txmAmtModifier, qrType, secretString) {
    let rec0 = "";
    let rec1 = "";
    let rec2 = "";
    let rec3 = "";
    let rec9 = "";
    let rec10 = "";

    if (!mid) {
        mid = "UNKNOWN";
    }
    if (!tid) {
        tid = "UNKNOWN";
    }
    rec0 = "0011SG.COM.NETS";

    let qrMetadata = version + qrIssuerUen + qrTimestamp;
    rec1 = "01" + qrMetadata.length + qrMetadata;

    if (mid) {
        let rec2Len;
        if (mid.length < 10) {
            rec2Len = "0" + mid.length;
        } else {
            rec2Len = "" + mid.length;
        }
        rec2 = "02" + rec2Len + mid;
    }

    if (tid) {
        let rec3Len;
        if (tid.length < 10) {
            rec3Len = "0" + tid.length;
        } else {
            rec3Len = "" + tid.length;
        }
        rec3 = "03" + rec3Len + tid;
    }

    if (txmAmtModifier) {
        let rec9Len;
        if (txmAmtModifier.length < 10) {
            rec9Len = "0" + txmAmtModifier.length;
        } else {
            rec9Len = "" + txmAmtModifier.length;
        }
        rec9 = "09" + rec9Len + txmAmtModifier;
    }

    if (qrType) {
        let rec10Len;
        if (qrType.length < 10) {
            rec10Len = "0" + qrType.length;
        } else {
            rec10Len = "" + qrType.length;
        }
        rec10 = "10" + rec10Len + qrType;
    }

    let preSigString = rec0 + rec1 + rec2 + rec3 + rec9 + rec10;

    let sig = "99" + "08" + generateSignature(preSigString, secretString).toUpperCase();
    let netsData = preSigString + sig;
    return "26" + netsData.length + netsData;
}

function makeTransplantedUatSgQr(mid, tid, merchantName) {
    if (!merchantName) {
        merchantName = "UNKNOWN";
    } else if (merchantName.length > 99) {
        merchantName = merchantName.substring(0, 99);
    }
    let secret = "THISISNETSSECRETSTRINGFORTESTING";
    let preNetsInfo = "000201010211";
    let postNetsinfoPreMerchantName = "51800007SG.SGQR01121808232F7399020701.00010306168730040201050200060400000708201808235204000053037025802SG";
    let postMerchantNamePreCrcData = "6009Singapore6304";
    let netsInfo = makeNetsMerchantSgQrObject(mid, tid, secret);
    let merchantNameRecord = "59" + merchantName.length + merchantName;

    let preCrc = preNetsInfo + netsInfo + postNetsinfoPreMerchantName + merchantNameRecord + postMerchantNamePreCrcData;
    let crc = crc16(preCrc);
    let crcAsHex = Number(crc).toString(16);
    if (crcAsHex.length < 4) {
        let lengthDiff = 4 - crcAsHex.length;
        crcAsHex = "0000".substring(0, lengthDiff) + crcAsHex;
    }

    return preCrc + crcAsHex.toUpperCase();
}


function makeNetsMerchantSgQrObject(mid, tid, secretString) {
    if (!mid) {
        mid = "UNKNOWN";
    } else if (mid.length > 99) {
        mid = mid.substring(0, 99);
    }
    if (!tid) {
        tid = "UNKNOWN";
    } else if (tid.length > 99) {
        tid = tid.substring(0, 99);
    }
    let rec0 = "0011SG.COM.NETS";
    let rec1 = "012310123456789991231235900";
    let rec2Len;
    if (mid.length < 10) {
        rec2Len = "0" + mid.length;
    } else {
        rec2Len = "" + mid.length;
    }
    let rec2 = "02" + rec2Len + mid;

    let rec3Len;
    if (tid.length < 10) {
        rec3Len = "0" + tid.length;
    } else {
        rec3Len = "" + tid.length;
    }
    let rec3 = "03" + rec3Len + tid;
    let preSigString = rec0 + rec1 + rec2 + rec3;

    let sig = "99" + "08" + generateSignature(preSigString, secretString).toUpperCase();
    let netsData = preSigString + sig;
    return "26" + netsData.length + netsData;
}

function generateSignature(data, secretString) {
    let dataWithSecret = data + secretString;
    let hash = sha256.create();
    hash.update(dataWithSecret);
    let signatureAsHex = hash.hex();
    return signatureAsHex.substring(0, 8);
}

//region::CRC16
let crcTable = [0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5,
    0x60c6, 0x70e7, 0x8108, 0x9129, 0xa14a, 0xb16b,
    0xc18c, 0xd1ad, 0xe1ce, 0xf1ef, 0x1231, 0x0210,
    0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
    0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c,
    0xf3ff, 0xe3de, 0x2462, 0x3443, 0x0420, 0x1401,
    0x64e6, 0x74c7, 0x44a4, 0x5485, 0xa56a, 0xb54b,
    0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6,
    0x5695, 0x46b4, 0xb75b, 0xa77a, 0x9719, 0x8738,
    0xf7df, 0xe7fe, 0xd79d, 0xc7bc, 0x48c4, 0x58e5,
    0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969,
    0xa90a, 0xb92b, 0x5af5, 0x4ad4, 0x7ab7, 0x6a96,
    0x1a71, 0x0a50, 0x3a33, 0x2a12, 0xdbfd, 0xcbdc,
    0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03,
    0x0c60, 0x1c41, 0xedae, 0xfd8f, 0xcdec, 0xddcd,
    0xad2a, 0xbd0b, 0x8d68, 0x9d49, 0x7e97, 0x6eb6,
    0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
    0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a,
    0x9f59, 0x8f78, 0x9188, 0x81a9, 0xb1ca, 0xa1eb,
    0xd10c, 0xc12d, 0xf14e, 0xe16f, 0x1080, 0x00a1,
    0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c,
    0xe37f, 0xf35e, 0x02b1, 0x1290, 0x22f3, 0x32d2,
    0x4235, 0x5214, 0x6277, 0x7256, 0xb5ea, 0xa5cb,
    0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
    0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447,
    0x5424, 0x4405, 0xa7db, 0xb7fa, 0x8799, 0x97b8,
    0xe75f, 0xf77e, 0xc71d, 0xd73c, 0x26d3, 0x36f2,
    0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9,
    0xb98a, 0xa9ab, 0x5844, 0x4865, 0x7806, 0x6827,
    0x18c0, 0x08e1, 0x3882, 0x28a3, 0xcb7d, 0xdb5c,
    0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
    0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0,
    0x2ab3, 0x3a92, 0xfd2e, 0xed0f, 0xdd6c, 0xcd4d,
    0xbdaa, 0xad8b, 0x9de8, 0x8dc9, 0x7c26, 0x6c07,
    0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba,
    0x8fd9, 0x9ff8, 0x6e17, 0x7e36, 0x4e55, 0x5e74,
    0x2e93, 0x3eb2, 0x0ed1, 0x1ef0];


function crc16_org(inputString) {
    let crc = 0xFFFF;
    let j, i;

    let c;
    for (i = 0; i < inputString.length; i++) {
        c = inputString.charCodeAt(i);
        if (c > 255) {
            console.log("Error for character: " + c);
            throw new RangeError();
        }
        j = (c ^ (crc >> 8)) & 0xFF;
        crc = crcTable[j] ^ (crc << 8);
    }
    return ((crc ^ 0) & 0xFFFF);
}

function crc16(inputString) {
    let crc = 0xFFFF;
    let j, i;

    let c;

    let bytes = toUTF8Array(inputString);
    for (i = 0; i < bytes.length; i++) {
        c = bytes[i];
        if (c > 255) {
            console.log("Error for character: " + c);
            throw new RangeError();
        }
        j = (c ^ (crc >> 8)) & 0xFF;
        crc = crcTable[j] ^ (crc << 8);
    }
    return ((crc ^ 0) & 0xFFFF);
}

function toUTF8Array(str) {
    var utf8 = [];
    for (var i = 0; i < str.length; i++) {
        var charcode = str.charCodeAt(i);
        if (charcode < 0x80) utf8.push(charcode);
        else if (charcode < 0x800) {
            utf8.push(0xc0 | (charcode >> 6),
                0x80 | (charcode & 0x3f));
        }
        else if (charcode < 0xd800 || charcode >= 0xe000) {
            utf8.push(0xe0 | (charcode >> 12),
                0x80 | ((charcode >> 6) & 0x3f),
                0x80 | (charcode & 0x3f));
        }
        // surrogate pair
        else {
            i++;
            // UTF-16 encodes 0x10000-0x10FFFF by
            // subtracting 0x10000 and splitting the
            // 20 bits of 0x0-0xFFFFF into two halves
            charcode = 0x10000 + (((charcode & 0x3ff) << 10)
                | (str.charCodeAt(i) & 0x3ff));
            utf8.push(0xf0 | (charcode >> 18),
                0x80 | ((charcode >> 12) & 0x3f),
                0x80 | ((charcode >> 6) & 0x3f),
                0x80 | (charcode & 0x3f));
        }
    }
    return utf8;
}

//endregion

//region::SHA256
/**
 * [js-sha256]{@link https://github.com/emn178/js-sha256}
 *
 * @version 0.9.0
 * @author Chen, Yi-Cyuan [emn178@gmail.com]
 * @copyright Chen, Yi-Cyuan 2014-2017
 * @license MIT
 */
/*
Copyright (c) 2014-2017 Chen, Yi-Cyuan

MIT License

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */


/*jslint bitwise: true */
(function () {
    'use strict';

    var ERROR = 'input is invalid type';
    var WINDOW = typeof window === 'object';
    var root = WINDOW ? window : {};
    if (root.JS_SHA256_NO_WINDOW) {
        WINDOW = false;
    }
    var WEB_WORKER = !WINDOW && typeof self === 'object';
    var NODE_JS = !root.JS_SHA256_NO_NODE_JS && typeof process === 'object' && process.versions && process.versions.node;
    if (NODE_JS) {
        root = global;
    } else if (WEB_WORKER) {
        root = self;
    }
    var COMMON_JS = !root.JS_SHA256_NO_COMMON_JS && typeof module === 'object' && module.exports;
    var AMD = typeof define === 'function' && define.amd;
    var ARRAY_BUFFER = !root.JS_SHA256_NO_ARRAY_BUFFER && typeof ArrayBuffer !== 'undefined';
    var HEX_CHARS = '0123456789abcdef'.split('');
    var EXTRA = [-2147483648, 8388608, 32768, 128];
    var SHIFT = [24, 16, 8, 0];
    var K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    var OUTPUT_TYPES = ['hex', 'array', 'digest', 'arrayBuffer'];

    var blocks = [];

    if (root.JS_SHA256_NO_NODE_JS || !Array.isArray) {
        Array.isArray = function (obj) {
            return Object.prototype.toString.call(obj) === '[object Array]';
        };
    }

    if (ARRAY_BUFFER && (root.JS_SHA256_NO_ARRAY_BUFFER_IS_VIEW || !ArrayBuffer.isView)) {
        ArrayBuffer.isView = function (obj) {
            return typeof obj === 'object' && obj.buffer && obj.buffer.constructor === ArrayBuffer;
        };
    }

    var createOutputMethod = function (outputType, is224) {
        return function (message) {
            return new Sha256(is224, true).update(message)[outputType]();
        };
    };

    var createMethod = function (is224) {
        var method = createOutputMethod('hex', is224);
        if (NODE_JS) {
            method = nodeWrap(method, is224);
        }
        method.create = function () {
            return new Sha256(is224);
        };
        method.update = function (message) {
            return method.create().update(message);
        };
        for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
            var type = OUTPUT_TYPES[i];
            method[type] = createOutputMethod(type, is224);
        }
        return method;
    };

    var nodeWrap = function (method, is224) {
        var crypto = eval("require('crypto')");
        var Buffer = eval("require('buffer').Buffer");
        var algorithm = is224 ? 'sha224' : 'sha256';
        var nodeMethod = function (message) {
            if (typeof message === 'string') {
                return crypto.createHash(algorithm).update(message, 'utf8').digest('hex');
            } else {
                if (message === null || message === undefined) {
                    throw new Error(ERROR);
                } else if (message.constructor === ArrayBuffer) {
                    message = new Uint8Array(message);
                }
            }
            if (Array.isArray(message) || ArrayBuffer.isView(message) ||
                message.constructor === Buffer) {
                return crypto.createHash(algorithm).update(new Buffer(message)).digest('hex');
            } else {
                return method(message);
            }
        };
        return nodeMethod;
    };

    var createHmacOutputMethod = function (outputType, is224) {
        return function (key, message) {
            return new HmacSha256(key, is224, true).update(message)[outputType]();
        };
    };

    var createHmacMethod = function (is224) {
        var method = createHmacOutputMethod('hex', is224);
        method.create = function (key) {
            return new HmacSha256(key, is224);
        };
        method.update = function (key, message) {
            return method.create(key).update(message);
        };
        for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
            var type = OUTPUT_TYPES[i];
            method[type] = createHmacOutputMethod(type, is224);
        }
        return method;
    };

    function Sha256(is224, sharedMemory) {
        if (sharedMemory) {
            blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] =
                blocks[4] = blocks[5] = blocks[6] = blocks[7] =
                    blocks[8] = blocks[9] = blocks[10] = blocks[11] =
                        blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
            this.blocks = blocks;
        } else {
            this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        }

        if (is224) {
            this.h0 = 0xc1059ed8;
            this.h1 = 0x367cd507;
            this.h2 = 0x3070dd17;
            this.h3 = 0xf70e5939;
            this.h4 = 0xffc00b31;
            this.h5 = 0x68581511;
            this.h6 = 0x64f98fa7;
            this.h7 = 0xbefa4fa4;
        } else { // 256
            this.h0 = 0x6a09e667;
            this.h1 = 0xbb67ae85;
            this.h2 = 0x3c6ef372;
            this.h3 = 0xa54ff53a;
            this.h4 = 0x510e527f;
            this.h5 = 0x9b05688c;
            this.h6 = 0x1f83d9ab;
            this.h7 = 0x5be0cd19;
        }

        this.block = this.start = this.bytes = this.hBytes = 0;
        this.finalized = this.hashed = false;
        this.first = true;
        this.is224 = is224;
    }

    Sha256.prototype.update = function (message) {
        if (this.finalized) {
            return;
        }
        var notString, type = typeof message;
        if (type !== 'string') {
            if (type === 'object') {
                if (message === null) {
                    throw new Error(ERROR);
                } else if (ARRAY_BUFFER && message.constructor === ArrayBuffer) {
                    message = new Uint8Array(message);
                } else if (!Array.isArray(message)) {
                    if (!ARRAY_BUFFER || !ArrayBuffer.isView(message)) {
                        throw new Error(ERROR);
                    }
                }
            } else {
                throw new Error(ERROR);
            }
            notString = true;
        }
        var code, index = 0, i, length = message.length, blocks = this.blocks;

        while (index < length) {
            if (this.hashed) {
                this.hashed = false;
                blocks[0] = this.block;
                blocks[16] = blocks[1] = blocks[2] = blocks[3] =
                    blocks[4] = blocks[5] = blocks[6] = blocks[7] =
                        blocks[8] = blocks[9] = blocks[10] = blocks[11] =
                            blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
            }

            if (notString) {
                for (i = this.start; index < length && i < 64; ++index) {
                    blocks[i >> 2] |= message[index] << SHIFT[i++ & 3];
                }
            } else {
                for (i = this.start; index < length && i < 64; ++index) {
                    code = message.charCodeAt(index);
                    if (code < 0x80) {
                        blocks[i >> 2] |= code << SHIFT[i++ & 3];
                    } else if (code < 0x800) {
                        blocks[i >> 2] |= (0xc0 | (code >> 6)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                    } else if (code < 0xd800 || code >= 0xe000) {
                        blocks[i >> 2] |= (0xe0 | (code >> 12)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                    } else {
                        code = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
                        blocks[i >> 2] |= (0xf0 | (code >> 18)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | ((code >> 12) & 0x3f)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                    }
                }
            }

            this.lastByteIndex = i;
            this.bytes += i - this.start;
            if (i >= 64) {
                this.block = blocks[16];
                this.start = i - 64;
                this.hash();
                this.hashed = true;
            } else {
                this.start = i;
            }
        }
        if (this.bytes > 4294967295) {
            this.hBytes += this.bytes / 4294967296 << 0;
            this.bytes = this.bytes % 4294967296;
        }
        return this;
    };

    Sha256.prototype.finalize = function () {
        if (this.finalized) {
            return;
        }
        this.finalized = true;
        var blocks = this.blocks, i = this.lastByteIndex;
        blocks[16] = this.block;
        blocks[i >> 2] |= EXTRA[i & 3];
        this.block = blocks[16];
        if (i >= 56) {
            if (!this.hashed) {
                this.hash();
            }
            blocks[0] = this.block;
            blocks[16] = blocks[1] = blocks[2] = blocks[3] =
                blocks[4] = blocks[5] = blocks[6] = blocks[7] =
                    blocks[8] = blocks[9] = blocks[10] = blocks[11] =
                        blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
        }
        blocks[14] = this.hBytes << 3 | this.bytes >>> 29;
        blocks[15] = this.bytes << 3;
        this.hash();
    };

    Sha256.prototype.hash = function () {
        var a = this.h0, b = this.h1, c = this.h2, d = this.h3, e = this.h4, f = this.h5, g = this.h6,
            h = this.h7, blocks = this.blocks, j, s0, s1, maj, t1, t2, ch, ab, da, cd, bc;

        for (j = 16; j < 64; ++j) {
            // rightrotate
            t1 = blocks[j - 15];
            s0 = ((t1 >>> 7) | (t1 << 25)) ^ ((t1 >>> 18) | (t1 << 14)) ^ (t1 >>> 3);
            t1 = blocks[j - 2];
            s1 = ((t1 >>> 17) | (t1 << 15)) ^ ((t1 >>> 19) | (t1 << 13)) ^ (t1 >>> 10);
            blocks[j] = blocks[j - 16] + s0 + blocks[j - 7] + s1 << 0;
        }

        bc = b & c;
        for (j = 0; j < 64; j += 4) {
            if (this.first) {
                if (this.is224) {
                    ab = 300032;
                    t1 = blocks[0] - 1413257819;
                    h = t1 - 150054599 << 0;
                    d = t1 + 24177077 << 0;
                } else {
                    ab = 704751109;
                    t1 = blocks[0] - 210244248;
                    h = t1 - 1521486534 << 0;
                    d = t1 + 143694565 << 0;
                }
                this.first = false;
            } else {
                s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
                s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
                ab = a & b;
                maj = ab ^ (a & c) ^ bc;
                ch = (e & f) ^ (~e & g);
                t1 = h + s1 + ch + K[j] + blocks[j];
                t2 = s0 + maj;
                h = d + t1 << 0;
                d = t1 + t2 << 0;
            }
            s0 = ((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10));
            s1 = ((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7));
            da = d & a;
            maj = da ^ (d & b) ^ ab;
            ch = (h & e) ^ (~h & f);
            t1 = g + s1 + ch + K[j + 1] + blocks[j + 1];
            t2 = s0 + maj;
            g = c + t1 << 0;
            c = t1 + t2 << 0;
            s0 = ((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10));
            s1 = ((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7));
            cd = c & d;
            maj = cd ^ (c & a) ^ da;
            ch = (g & h) ^ (~g & e);
            t1 = f + s1 + ch + K[j + 2] + blocks[j + 2];
            t2 = s0 + maj;
            f = b + t1 << 0;
            b = t1 + t2 << 0;
            s0 = ((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10));
            s1 = ((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7));
            bc = b & c;
            maj = bc ^ (b & d) ^ cd;
            ch = (f & g) ^ (~f & h);
            t1 = e + s1 + ch + K[j + 3] + blocks[j + 3];
            t2 = s0 + maj;
            e = a + t1 << 0;
            a = t1 + t2 << 0;
        }

        this.h0 = this.h0 + a << 0;
        this.h1 = this.h1 + b << 0;
        this.h2 = this.h2 + c << 0;
        this.h3 = this.h3 + d << 0;
        this.h4 = this.h4 + e << 0;
        this.h5 = this.h5 + f << 0;
        this.h6 = this.h6 + g << 0;
        this.h7 = this.h7 + h << 0;
    };

    Sha256.prototype.hex = function () {
        this.finalize();

        var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4, h5 = this.h5,
            h6 = this.h6, h7 = this.h7;

        var hex = HEX_CHARS[(h0 >> 28) & 0x0F] + HEX_CHARS[(h0 >> 24) & 0x0F] +
            HEX_CHARS[(h0 >> 20) & 0x0F] + HEX_CHARS[(h0 >> 16) & 0x0F] +
            HEX_CHARS[(h0 >> 12) & 0x0F] + HEX_CHARS[(h0 >> 8) & 0x0F] +
            HEX_CHARS[(h0 >> 4) & 0x0F] + HEX_CHARS[h0 & 0x0F] +
            HEX_CHARS[(h1 >> 28) & 0x0F] + HEX_CHARS[(h1 >> 24) & 0x0F] +
            HEX_CHARS[(h1 >> 20) & 0x0F] + HEX_CHARS[(h1 >> 16) & 0x0F] +
            HEX_CHARS[(h1 >> 12) & 0x0F] + HEX_CHARS[(h1 >> 8) & 0x0F] +
            HEX_CHARS[(h1 >> 4) & 0x0F] + HEX_CHARS[h1 & 0x0F] +
            HEX_CHARS[(h2 >> 28) & 0x0F] + HEX_CHARS[(h2 >> 24) & 0x0F] +
            HEX_CHARS[(h2 >> 20) & 0x0F] + HEX_CHARS[(h2 >> 16) & 0x0F] +
            HEX_CHARS[(h2 >> 12) & 0x0F] + HEX_CHARS[(h2 >> 8) & 0x0F] +
            HEX_CHARS[(h2 >> 4) & 0x0F] + HEX_CHARS[h2 & 0x0F] +
            HEX_CHARS[(h3 >> 28) & 0x0F] + HEX_CHARS[(h3 >> 24) & 0x0F] +
            HEX_CHARS[(h3 >> 20) & 0x0F] + HEX_CHARS[(h3 >> 16) & 0x0F] +
            HEX_CHARS[(h3 >> 12) & 0x0F] + HEX_CHARS[(h3 >> 8) & 0x0F] +
            HEX_CHARS[(h3 >> 4) & 0x0F] + HEX_CHARS[h3 & 0x0F] +
            HEX_CHARS[(h4 >> 28) & 0x0F] + HEX_CHARS[(h4 >> 24) & 0x0F] +
            HEX_CHARS[(h4 >> 20) & 0x0F] + HEX_CHARS[(h4 >> 16) & 0x0F] +
            HEX_CHARS[(h4 >> 12) & 0x0F] + HEX_CHARS[(h4 >> 8) & 0x0F] +
            HEX_CHARS[(h4 >> 4) & 0x0F] + HEX_CHARS[h4 & 0x0F] +
            HEX_CHARS[(h5 >> 28) & 0x0F] + HEX_CHARS[(h5 >> 24) & 0x0F] +
            HEX_CHARS[(h5 >> 20) & 0x0F] + HEX_CHARS[(h5 >> 16) & 0x0F] +
            HEX_CHARS[(h5 >> 12) & 0x0F] + HEX_CHARS[(h5 >> 8) & 0x0F] +
            HEX_CHARS[(h5 >> 4) & 0x0F] + HEX_CHARS[h5 & 0x0F] +
            HEX_CHARS[(h6 >> 28) & 0x0F] + HEX_CHARS[(h6 >> 24) & 0x0F] +
            HEX_CHARS[(h6 >> 20) & 0x0F] + HEX_CHARS[(h6 >> 16) & 0x0F] +
            HEX_CHARS[(h6 >> 12) & 0x0F] + HEX_CHARS[(h6 >> 8) & 0x0F] +
            HEX_CHARS[(h6 >> 4) & 0x0F] + HEX_CHARS[h6 & 0x0F];
        if (!this.is224) {
            hex += HEX_CHARS[(h7 >> 28) & 0x0F] + HEX_CHARS[(h7 >> 24) & 0x0F] +
                HEX_CHARS[(h7 >> 20) & 0x0F] + HEX_CHARS[(h7 >> 16) & 0x0F] +
                HEX_CHARS[(h7 >> 12) & 0x0F] + HEX_CHARS[(h7 >> 8) & 0x0F] +
                HEX_CHARS[(h7 >> 4) & 0x0F] + HEX_CHARS[h7 & 0x0F];
        }
        return hex;
    };

    Sha256.prototype.toString = Sha256.prototype.hex;

    Sha256.prototype.digest = function () {
        this.finalize();

        var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4, h5 = this.h5,
            h6 = this.h6, h7 = this.h7;

        var arr = [
            (h0 >> 24) & 0xFF, (h0 >> 16) & 0xFF, (h0 >> 8) & 0xFF, h0 & 0xFF,
            (h1 >> 24) & 0xFF, (h1 >> 16) & 0xFF, (h1 >> 8) & 0xFF, h1 & 0xFF,
            (h2 >> 24) & 0xFF, (h2 >> 16) & 0xFF, (h2 >> 8) & 0xFF, h2 & 0xFF,
            (h3 >> 24) & 0xFF, (h3 >> 16) & 0xFF, (h3 >> 8) & 0xFF, h3 & 0xFF,
            (h4 >> 24) & 0xFF, (h4 >> 16) & 0xFF, (h4 >> 8) & 0xFF, h4 & 0xFF,
            (h5 >> 24) & 0xFF, (h5 >> 16) & 0xFF, (h5 >> 8) & 0xFF, h5 & 0xFF,
            (h6 >> 24) & 0xFF, (h6 >> 16) & 0xFF, (h6 >> 8) & 0xFF, h6 & 0xFF
        ];
        if (!this.is224) {
            arr.push((h7 >> 24) & 0xFF, (h7 >> 16) & 0xFF, (h7 >> 8) & 0xFF, h7 & 0xFF);
        }
        return arr;
    };

    Sha256.prototype.array = Sha256.prototype.digest;

    Sha256.prototype.arrayBuffer = function () {
        this.finalize();

        var buffer = new ArrayBuffer(this.is224 ? 28 : 32);
        var dataView = new DataView(buffer);
        dataView.setUint32(0, this.h0);
        dataView.setUint32(4, this.h1);
        dataView.setUint32(8, this.h2);
        dataView.setUint32(12, this.h3);
        dataView.setUint32(16, this.h4);
        dataView.setUint32(20, this.h5);
        dataView.setUint32(24, this.h6);
        if (!this.is224) {
            dataView.setUint32(28, this.h7);
        }
        return buffer;
    };

    function HmacSha256(key, is224, sharedMemory) {
        var i, type = typeof key;
        if (type === 'string') {
            var bytes = [], length = key.length, index = 0, code;
            for (i = 0; i < length; ++i) {
                code = key.charCodeAt(i);
                if (code < 0x80) {
                    bytes[index++] = code;
                } else if (code < 0x800) {
                    bytes[index++] = (0xc0 | (code >> 6));
                    bytes[index++] = (0x80 | (code & 0x3f));
                } else if (code < 0xd800 || code >= 0xe000) {
                    bytes[index++] = (0xe0 | (code >> 12));
                    bytes[index++] = (0x80 | ((code >> 6) & 0x3f));
                    bytes[index++] = (0x80 | (code & 0x3f));
                } else {
                    code = 0x10000 + (((code & 0x3ff) << 10) | (key.charCodeAt(++i) & 0x3ff));
                    bytes[index++] = (0xf0 | (code >> 18));
                    bytes[index++] = (0x80 | ((code >> 12) & 0x3f));
                    bytes[index++] = (0x80 | ((code >> 6) & 0x3f));
                    bytes[index++] = (0x80 | (code & 0x3f));
                }
            }
            key = bytes;
        } else {
            if (type === 'object') {
                if (key === null) {
                    throw new Error(ERROR);
                } else if (ARRAY_BUFFER && key.constructor === ArrayBuffer) {
                    key = new Uint8Array(key);
                } else if (!Array.isArray(key)) {
                    if (!ARRAY_BUFFER || !ArrayBuffer.isView(key)) {
                        throw new Error(ERROR);
                    }
                }
            } else {
                throw new Error(ERROR);
            }
        }

        if (key.length > 64) {
            key = (new Sha256(is224, true)).update(key).array();
        }

        var oKeyPad = [], iKeyPad = [];
        for (i = 0; i < 64; ++i) {
            var b = key[i] || 0;
            oKeyPad[i] = 0x5c ^ b;
            iKeyPad[i] = 0x36 ^ b;
        }

        Sha256.call(this, is224, sharedMemory);

        this.update(iKeyPad);
        this.oKeyPad = oKeyPad;
        this.inner = true;
        this.sharedMemory = sharedMemory;
    }

    HmacSha256.prototype = new Sha256();

    HmacSha256.prototype.finalize = function () {
        Sha256.prototype.finalize.call(this);
        if (this.inner) {
            this.inner = false;
            var innerHash = this.array();
            Sha256.call(this, this.is224, this.sharedMemory);
            this.update(this.oKeyPad);
            this.update(innerHash);
            Sha256.prototype.finalize.call(this);
        }
    };

    var exports = createMethod();
    exports.sha256 = exports;
    exports.sha224 = createMethod(true);
    exports.sha256.hmac = createHmacMethod();
    exports.sha224.hmac = createHmacMethod(true);

    if (COMMON_JS) {
        module.exports = exports;
    } else {
        root.sha256 = exports.sha256;
        root.sha224 = exports.sha224;
        if (AMD) {
            define(function () {
                return exports;
            });
        }
    }
})();
//endregion

