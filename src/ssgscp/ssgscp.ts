
import * as crypto from 'node:crypto';
import { Buffer } from "node:buffer";


// Define the SSGSCP packet types
export const enum PacketType {
    CONN = 1, // connection request
    CONNACPT = 2, // connection accept (server to gateway)
    CONNFAIL = 3, // connection failure (server to gateway)
    RCPTOK = 10, // message received successfully (both directions)
    MSGCONF = 20, // set configuration parameters (server to gateway)
    MSGSTATUS = 21, // a sensor seal status update (gateway to server)
};

// Define the SSGSCP MSG subtypes
export const enum MessageSubtype {
    INVALID = 0x00,

    PING_PONG = 0x01, // A message to the server from the gateway back to the server to test the connection. Payload is an incremented sequence number, u8.
    REMOTE_TERMINAL_INPUT = 0x02, // A message to the gateway to be processed by the gateway's remote terminal service
    GATEWAY_RESTART = 0x03, 
    SET_RADIO_PARAMS = 0x04, // A message to the gateway to set the gateway's radio parameters
    SEND_PACKET = 0x05, // A message to the gateway to send a packet
    RESET_RADIO_PARAMS = 0x06, // A message to the gateway to reset the gateway's radio parameters to their default values
    WFU_PACKET = 0x07, // A message to the gateway to send a WFU packet: u16 FW Version, u16 total num FW blocks, u8 this num FW blocks, blocks [ { u16 block num, u8[32] block data } ... ]

    // Gateway -> Server
    REMOTE_TERMINAL_OUTPUT = 0x03, // A message from the gateway's remote terminal service to the web client
    WAKEUP_SCAN = 0x04, // A message from the gateway to the server containing a wakeup scan result
    SSRB_UPDATE = 0x53, // A message from the gateway to the server containing an SSRB update from a Sensor Seal
};



// Define the SSGSCP packet fields
export type ParsedSSGSCPPacket = {
    authSuccess?: true | false, // true if the encryption authentication code is valid ([0, 1, 2, 3]), false if not
    packetType?: PacketType, // the packet type
    encryptionAuthenticationCode?: Buffer | Buffer, // the encryption authentication code
    gatewayUID?: Buffer | Buffer, // the gateway UID
    packetID?: number, // the packet ID
    payload?: Buffer | Buffer // the packet payload
};

/**
 * This class defines various static methods for parsing and constructing
 * SSGSCP packets
 */
export class SSGSCP {

    static PACKET_IDENTIFIER = Buffer.from([83, 83, 71, 83, 67, 80]); // Packet Identifier is 6 bytes, "SSGSCP"

    /**
    * Packs and encrypts SSGSCP fields into their packet form
    * @param {Object} packet an object containing the SSGSCP packet fields (packetType, gatewayUID, packetID, payload)
    * @param {Buffer} key the key used to encrypt the encrypted portion of the packet
    * @returns {Buffer} a byte array containing the packed SSGSCP packet
    */
    static async packSSGSCP(packet: ParsedSSGSCPPacket, key: Buffer | Buffer): Promise<Buffer | null> {
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
        const encryptedPortionPlaintextUnpaddedLength = 8 + packet.payload.length;
        const encryptedPortionPlaintext = Buffer.alloc(encryptedPortionPlaintextUnpaddedLength + (4 - encryptedPortionPlaintextUnpaddedLength % 4));

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
        const iv = Buffer.alloc(16);
        iv.set(crypto.randomBytes(8), 0);

        // Encrypt the encrypted portion
        // const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
        // const encryptedPortion = Buffer.concat([cipher.update(encryptedPortionPlaintext), cipher.final()]);

        const importedKey = await crypto.subtle.importKey(
            "raw",
            new Uint8Array(key),
            "AES-CTR",
            true,
            ["encrypt", "decrypt"]
        );
        
        const encryptedPortion = Buffer.from(await crypto.subtle.encrypt(
            {
                name: "AES-CTR",
                counter: iv,
                length: 64
            },
            importedKey,
            encryptedPortionPlaintext
            
        ));

        // Pack the packet
        const packedPacket = Buffer.alloc(18 + encryptedPortion.length);
        packedPacket.set(SSGSCP.PACKET_IDENTIFIER, 0); // Packet Identifier is 6 bytes
        packedPacket.set(iv, 6); // IV is 8 bytes
        packedPacket.set(packet.gatewayUID, 14); // Gateway UID is 4 bytes
        packedPacket.set(encryptedPortion, 18); // Encrypted portion is variable length

        return packedPacket;
    }

    /**
     * Tries to parses a UDP datagram containing an SSGSCP packet
     * @static
     * @param {Buffer} datagram the datagram containing the SSGSCP packet to parse
     * @param {Buffer} key the key used to decrypt the encrypted portion of the packet
     * @returns {Object} the parsed SSGSCP packet fields or null if the packet cannot be parsed
     */
    static async parseSSGSCP(datagram: Buffer, key: Buffer): Promise<ParsedSSGSCPPacket> {
        if (!SSGSCP.isSSGSCP(datagram)) // Check if the datagram is an SSGSCP packet
            return null;

        // Extract the fields from the datagram

        const iv8 = datagram.subarray(6, 14); // IV is 8 bytes
        const gatewayUID = datagram.subarray(14, 18); // Gateway UID is 4 bytes
        const encryptedPortion = datagram.subarray(18); // Encrypted portion is variable length

        const iv16 = Buffer.alloc(16); // Create a 16-byte IV with 8 bytes of right padding
        iv16.set(iv8, 0);

        // Decrypt the encrypted portion
        // const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv16);
        // const decrypted = decipher.update(encryptedPortion);
        // const final = decipher.final();
        // const decryptedPortion = Buffer.concat([decrypted, final]);
        const importedKey = await crypto.subtle.importKey(
            "raw",
            new Uint8Array(key),
            "AES-CTR",
            true,
            ["encrypt", "decrypt"]
        );
        
        const decryptedPortion = Buffer.from(await crypto.subtle.decrypt(
            {
                name: "AES-CTR",
                counter: iv16,
                length: 64
            },
            importedKey,
            new Uint8Array(encryptedPortion)
        ));

        // Extract the fields from the decrypted portion
        const packetType = decryptedPortion[0]; // Packet Type is 1 byte
        const encryptionAuthenticationCode = decryptedPortion.subarray(1, 1 + 4); // Encryption Authentication Code is 4 bytes
        const packetID = SSGSCP.getU16BE(decryptedPortion.subarray(5, 5 + 2)); // Packet ID is 2 bytes, big endian, unsigned integer
        const payloadLength = decryptedPortion[7]; // Payload Length is 1 byte
        const payload = decryptedPortion.subarray(8, 8 + payloadLength); // Payload is variable length

        // Encryption authentication code should contain [0, 1, 2, 3] bytes 
        if (!bufferContainsValues(encryptionAuthenticationCode, 0, [0, 1, 2, 3])) {
            this.errMsg = 'Invalid encryption authentication code';
            return {
                authSuccess: false,
            };
        }

        return <ParsedSSGSCPPacket>{
            authSuccess: true,
            packetType,
            encryptionAuthenticationCode,
            gatewayUID,
            packetID,
            payload
        };
    }

    /**
     * Tries to parse a UDP datagram containing an SSGSCP packet and returns the gateway UID
     * @static
     * @param {Buffer} datagram the datagram containing the SSGSCP packet to parse
     * @returns {Buffer} the gateway UID or null if the packet cannot be parsed
     */
    static parsePacketGatewayUID(datagram: Buffer): Buffer {
        if (!SSGSCP.isSSGSCP(datagram)) // Check if the datagram is an SSGSCP packet
            return null;

        // Extract the fields from the datagram
        return datagram.subarray(14, 18); // Gateway UID is 4 bytes
    }

    /**
     * Checks if a datagram has a valid SSGSCP packet
     * @static
     * @param {Buffer} datagram a udp datagram
     * @returns {boolean} true if the datagram contains a valid SSGSCP payload, false if not
     */
    static isSSGSCP(datagram: Buffer): boolean {
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
    }

    // obtains a 16-bit unsigned integer from a 2 byte array in big endian format
    static getU16BE(buffer: Buffer): number {
        return buffer[0] << 8 | buffer[1];
    }

    // returns a 2 byte array containing the 16-bit unsigned integer in big endian format
    static setU16BE(value: number): Buffer {
        return Buffer.from([value >> 8, value & 0xff]);
    }

    static errMsg: string = 'no error';
};

/**
 * Checks if a buffer contains a given array of values
 * @param {Buffer} buffer the buffer to check
 * @param {number} offset the offset in the buffer to start checking
 * @param {Buffer | Array<number>} array the array of values to check for
 * @returns {boolean} true if the buffer contains the array of values, false if not
 */
function bufferContainsValues(buffer: Buffer, offset: number, array: Buffer | Array<number>): boolean {
    for (let i = 0; i < array.length; i++) {
        if (buffer[i + offset] != array[i])
            return false;
    }

    return true;
}
