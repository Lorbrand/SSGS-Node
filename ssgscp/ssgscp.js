var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
import * as crypto from 'node:crypto';
import { Buffer } from "node:buffer";
;
;
/**
 * This class defines various static methods for parsing and constructing
 * SSGSCP packets
 */
var SSGSCP = /** @class */ (function () {
    function SSGSCP() {
    }
    /**
    * Packs and encrypts SSGSCP fields into their packet form
    * @param {Object} packet an object containing the SSGSCP packet fields (packetType, gatewayUID, packetID, payload)
    * @param {Buffer} key the key used to encrypt the encrypted portion of the packet
    * @returns {Buffer} a byte array containing the packed SSGSCP packet
    */
    SSGSCP.packSSGSCP = function (packet, key) {
        return __awaiter(this, void 0, void 0, function () {
            var encryptedPortionPlaintextUnpaddedLength, encryptedPortionPlaintext, iv, importedKey, encryptedPortion, _a, _b, packedPacket;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0:
                        // Ensure packetType is a 8-bit unsigned integer
                        if (packet.packetType < 0x00 || packet.packetType > 0xff) {
                            this.errMsg = 'packetType field should be a 8-bit unsigned integer';
                            return [2 /*return*/, null];
                        }
                        // Ensure gatewayUID is a 4-byte array if provided
                        if (packet.gatewayUID && packet.gatewayUID.length != 4) {
                            this.errMsg = 'gatewayUID field should be a 4-byte array if provided';
                            return [2 /*return*/, null];
                        }
                        // Ensure packetID is a 16-bit unsigned integer
                        if (packet.packetID < 0x00 || packet.packetID > 0xffff) {
                            this.errMsg = 'packetID field should be a 16-bit unsigned integer';
                            return [2 /*return*/, null];
                        }
                        if (!packet.payload) { // If no payload is provided, set it to an empty array
                            packet.payload = Buffer.alloc(0);
                        }
                        encryptedPortionPlaintextUnpaddedLength = 8 + packet.payload.length;
                        encryptedPortionPlaintext = Buffer.alloc(encryptedPortionPlaintextUnpaddedLength + (4 - encryptedPortionPlaintextUnpaddedLength % 4));
                        // Packet Type
                        encryptedPortionPlaintext.set([packet.packetType], 0);
                        // Encryption Authentication Code
                        encryptedPortionPlaintext.set([0, 1, 2, 3], 1);
                        // Packet ID
                        encryptedPortionPlaintext.set(SSGSCP.setU16BE(packet.packetID), 5);
                        // Payload Length
                        encryptedPortionPlaintext.set([packet.payload.length], 7);
                        // Payload
                        encryptedPortionPlaintext.set(packet.payload, 8);
                        iv = Buffer.alloc(16);
                        iv.set(crypto.randomBytes(8), 0);
                        return [4 /*yield*/, crypto.subtle.importKey("raw", new Uint8Array(key), "AES-CTR", true, ["encrypt", "decrypt"])];
                    case 1:
                        importedKey = _c.sent();
                        _b = (_a = Buffer).from;
                        return [4 /*yield*/, crypto.subtle.encrypt({
                                name: "AES-CTR",
                                counter: iv,
                                length: 64
                            }, importedKey, encryptedPortionPlaintext)];
                    case 2:
                        encryptedPortion = _b.apply(_a, [_c.sent()]);
                        packedPacket = Buffer.alloc(18 + encryptedPortion.length);
                        packedPacket.set(SSGSCP.PACKET_IDENTIFIER, 0); // Packet Identifier is 6 bytes
                        packedPacket.set(iv, 6); // IV is 8 bytes
                        packedPacket.set(packet.gatewayUID, 14); // Gateway UID is 4 bytes
                        packedPacket.set(encryptedPortion, 18); // Encrypted portion is variable length
                        return [2 /*return*/, packedPacket];
                }
            });
        });
    };
    /**
     * Tries to parses a UDP datagram containing an SSGSCP packet
     * @static
     * @param {Buffer} datagram the datagram containing the SSGSCP packet to parse
     * @param {Buffer} key the key used to decrypt the encrypted portion of the packet
     * @returns {Object} the parsed SSGSCP packet fields or null if the packet cannot be parsed
     */
    SSGSCP.parseSSGSCP = function (datagram, key) {
        return __awaiter(this, void 0, void 0, function () {
            var iv8, gatewayUID, encryptedPortion, iv16, importedKey, decryptedPortion, _a, _b, packetType, encryptionAuthenticationCode, packetID, payloadLength, payload;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0:
                        if (!SSGSCP.isSSGSCP(datagram)) // Check if the datagram is an SSGSCP packet
                            return [2 /*return*/, null];
                        iv8 = datagram.subarray(6, 14);
                        gatewayUID = datagram.subarray(14, 18);
                        encryptedPortion = datagram.subarray(18);
                        iv16 = Buffer.alloc(16);
                        iv16.set(iv8, 0);
                        return [4 /*yield*/, crypto.subtle.importKey("raw", new Uint8Array(key), "AES-CTR", true, ["encrypt", "decrypt"])];
                    case 1:
                        importedKey = _c.sent();
                        _b = (_a = Buffer).from;
                        return [4 /*yield*/, crypto.subtle.decrypt({
                                name: "AES-CTR",
                                counter: iv16,
                                length: 64
                            }, importedKey, new Uint8Array(encryptedPortion))];
                    case 2:
                        decryptedPortion = _b.apply(_a, [_c.sent()]);
                        packetType = decryptedPortion[0];
                        encryptionAuthenticationCode = decryptedPortion.subarray(1, 1 + 4);
                        packetID = SSGSCP.getU16BE(decryptedPortion.subarray(5, 5 + 2));
                        payloadLength = decryptedPortion[7];
                        payload = decryptedPortion.subarray(8, 8 + payloadLength);
                        // Encryption authentication code should contain [0, 1, 2, 3] bytes 
                        if (!bufferContainsValues(encryptionAuthenticationCode, 0, [0, 1, 2, 3])) {
                            this.errMsg = 'Invalid encryption authentication code';
                            return [2 /*return*/, {
                                    authSuccess: false,
                                }];
                        }
                        return [2 /*return*/, {
                                authSuccess: true,
                                packetType: packetType,
                                encryptionAuthenticationCode: encryptionAuthenticationCode,
                                gatewayUID: gatewayUID,
                                packetID: packetID,
                                payload: payload
                            }];
                }
            });
        });
    };
    /**
     * Tries to parse a UDP datagram containing an SSGSCP packet and returns the gateway UID
     * @static
     * @param {Buffer} datagram the datagram containing the SSGSCP packet to parse
     * @returns {Buffer} the gateway UID or null if the packet cannot be parsed
     */
    SSGSCP.parsePacketGatewayUID = function (datagram) {
        if (!SSGSCP.isSSGSCP(datagram)) // Check if the datagram is an SSGSCP packet
            return null;
        // Extract the fields from the datagram
        return datagram.subarray(14, 18); // Gateway UID is 4 bytes
    };
    /**
     * Checks if a datagram has a valid SSGSCP packet
     * @static
     * @param {Buffer} datagram a udp datagram
     * @returns {boolean} true if the datagram contains a valid SSGSCP payload, false if not
     */
    SSGSCP.isSSGSCP = function (datagram) {
        // The SSGSCP unencrypted header portion is 18 bytes, and the encrypted 
        // portion is at least 8 bytes
        if (datagram.length < 18 + 8) {
            this.errMsg = 'packet length too short';
            return false;
        }
        // SSGSCP packets start with 'SSGSCP'
        if (!bufferContainsValues(datagram, 0, SSGSCP.PACKET_IDENTIFIER)) {
            this.errMsg = 'packet does not begin with "SSGSCP"';
            return false;
        }
        return true;
    };
    // obtains a 16-bit unsigned integer from a 2 byte array in big endian format
    SSGSCP.getU16BE = function (buffer) {
        return buffer[0] << 8 | buffer[1];
    };
    // returns a 2 byte array containing the 16-bit unsigned integer in big endian format
    SSGSCP.setU16BE = function (value) {
        return Buffer.from([value >> 8, value & 0xff]);
    };
    SSGSCP.PACKET_IDENTIFIER = Buffer.from([83, 83, 71, 83, 67, 80]); // Packet Identifier is 6 bytes, "SSGSCP"
    SSGSCP.errMsg = 'no error';
    return SSGSCP;
}());
export { SSGSCP };
;
/**
 * Checks if a buffer contains a given array of values
 * @param {Buffer} buffer the buffer to check
 * @param {number} offset the offset in the buffer to start checking
 * @param {Buffer | Array<number>} array the array of values to check for
 * @returns {boolean} true if the buffer contains the array of values, false if not
 */
function bufferContainsValues(buffer, offset, array) {
    for (var i = 0; i < array.length; i++) {
        if (buffer[i + offset] != array[i])
            return false;
    }
    return true;
}
