import * as crypto from 'node:crypto';
;
;
/**
 * This class defines various static methods for parsing and constructing
 * SSGSCP packets
 */
export var SSGSCP = /** @class */ (function () {
    function SSGSCP() {
    }
    /**
    * Packs and encrypts SSGSCP fields into their packet form
    * @param {Object} packet an object containing the SSGSCP packet fields (packetType, gatewayUID, packetID, payload)
    * @param {Buffer} key the key used to encrypt the encrypted portion of the packet
    * @returns {Buffer} a byte array containing the packed SSGSCP packet
    */
    SSGSCP.packSSGSCP = function (packet, key) {
        // Ensure packetType is a 8-bit unsigned integer
        if (packet.packetType < 0x00 || packet.packetType > 0xff) {
            this.errMsg = 'packetType field should be a 8-bit unsigned integer';
            return null;
        }
        // Ensure gatewayUID is a 4-byte array if provided
        if (packet.gatewayUID && packet.gatewayUID.length != 4) {
            this.errMsg = 'gatewayUID field should be a 4-byte array if provided';
            return null;
        }
        // Ensure packetID is a 16-bit unsigned integer
        if (packet.packetID < 0x00 || packet.packetID > 0xffff) {
            this.errMsg = 'packetID field should be a 16-bit unsigned integer';
            return null;
        }
        if (!packet.payload) { // If no payload is provided, set it to an empty array
            packet.payload = Buffer.alloc(0);
        }
        // we want it padded to 4 bytes
        var encryptedPortionPlaintextUnpaddedLength = 8 + packet.payload.length;
        var encryptedPortionPlaintext = Buffer.alloc(encryptedPortionPlaintextUnpaddedLength + (4 - encryptedPortionPlaintextUnpaddedLength % 4));
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
        // Create a 16-byte IV with 8 bytes of right padding and 8 random bytes to the left
        var iv = Buffer.alloc(16);
        iv.set(crypto.randomBytes(8), 0);
        // Encrypt the encrypted portion
        var cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
        var encryptedPortion = Buffer.concat([cipher.update(encryptedPortionPlaintext), cipher.final()]);
        // Pack the packet
        var packedPacket = Buffer.alloc(18 + encryptedPortion.length);
        packedPacket.set(SSGSCP.PACKET_IDENTIFIER, 0); // Packet Identifier is 6 bytes
        packedPacket.set(iv, 6); // IV is 8 bytes
        packedPacket.set(packet.gatewayUID, 14); // Gateway UID is 4 bytes
        packedPacket.set(encryptedPortion, 18); // Encrypted portion is variable length
        return packedPacket;
    };
    /**
     * Tries to parses a UDP datagram containing an SSGSCP packet
     * @static
     * @param {Buffer} datagram the datagram containing the SSGSCP packet to parse
     * @param {Buffer} key the key used to decrypt the encrypted portion of the packet
     * @returns {Object} the parsed SSGSCP packet fields or null if the packet cannot be parsed
     */
    SSGSCP.parseSSGSCP = function (datagram, key) {
        if (!SSGSCP.isSSGSCP(datagram)) // Check if the datagram is an SSGSCP packet
            return null;
        // Extract the fields from the datagram
        var iv8 = datagram.subarray(6, 14); // IV is 8 bytes
        var gatewayUID = datagram.subarray(14, 18); // Gateway UID is 4 bytes
        var encryptedPortion = datagram.subarray(18); // Encrypted portion is variable length
        var iv16 = Buffer.alloc(16); // Create a 16-byte IV with 8 bytes of right padding
        iv16.set(iv8, 0);
        // Decrypt the encrypted portion
        var decipher = crypto.createDecipheriv('aes-256-ctr', key, iv16);
        var decrypted = decipher.update(encryptedPortion);
        var final = decipher.final();
        var decryptedPortion = Buffer.concat([decrypted, final]);
        // Extract the fields from the decrypted portion
        var packetType = decryptedPortion[0]; // Packet Type is 1 byte
        var encryptionAuthenticationCode = decryptedPortion.subarray(1, 1 + 4); // Encryption Authentication Code is 4 bytes
        var packetID = SSGSCP.getU16BE(decryptedPortion.subarray(5, 5 + 2)); // Packet ID is 2 bytes, big endian, unsigned integer
        var payloadLength = decryptedPortion[7]; // Payload Length is 1 byte
        var payload = decryptedPortion.subarray(8, 8 + payloadLength); // Payload is variable length
        // Encryption authentication code should contain [0, 1, 2, 3] bytes 
        if (!bufferContainsValues(encryptionAuthenticationCode, 0, [0, 1, 2, 3])) {
            this.errMsg = 'Invalid encryption authentication code';
            return {
                authSuccess: false,
            };
        }
        return {
            authSuccess: true,
            packetType: packetType,
            encryptionAuthenticationCode: encryptionAuthenticationCode,
            gatewayUID: gatewayUID,
            packetID: packetID,
            payload: payload
        };
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
