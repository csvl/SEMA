"use strict";

var iterateObject = require("iterate-object"),
    regexEscape = require("regex-escape"),
    he = require("he");

//const DECODE_MAP = require("./character-map")
//const ENCODE_MAP = {};
//
//iterateObject(DECODE_MAP, (value, name) => {
//    ENCODE_MAP[value] = name;
//});

module.exports = {
    /**
     * decode
     * Decodes an encoded string.
     *
     * @name decode
     * @function
     * @param {String} input The encoded string.
     * @returns {String} The decoded string.
     */
    decode: function decode(input) {
        return he.decode(input);
    }

    /**
     * encode
     * Encodes a string.
     *
     * @name encode
     * @function
     * @param {String} input The string that must be encoded.
     * @returns {String} The encoded string.
     */
    ,
    encode: function encode(input) {
        return he.encode(input);
    }
};