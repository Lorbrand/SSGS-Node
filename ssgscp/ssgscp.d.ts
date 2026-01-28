import { Buffer } from "node:buffer";
export declare const enum PacketType {
    CONN = 1,// connection request
    CONNACPT = 2,// connection accept (server to gateway)
    CONNFAIL = 3,// connection failure (server to gateway)
    RCPTOK = 10,// message received successfully (both directions)
    MSGCONF = 20,// set configuration parameters (server to gateway)
    MSGSTATUS = 21
}
export declare const enum MessageSubtype {
    INVALID = 0,
    PING_PONG = 1,// A message to the server from the gateway back to the server to test the connection. Payload is an incremented sequence number, u8.
    REMOTE_TERMINAL_INPUT = 2,// A message to the gateway to be processed by the gateway's remote terminal service
    GATEWAY_RESTART = 3,
    SET_RADIO_PARAMS = 4,// A message to the gateway to set the gateway's radio parameters
    SEND_PACKET = 5,// A message to the gateway to send a packet
    RESET_RADIO_PARAMS = 6,// A message to the gateway to reset the gateway's radio parameters to their default values
    WFU_PACKET = 7,// A message to the gateway to send a WFU packet: u16 FW Version, u16 total num FW blocks, u8 this num FW blocks, blocks [ { u16 block num, u8[32] block data } ... ]
    REMOTE_TERMINAL_OUTPUT = 3,// A message from the gateway's remote terminal service to the web client
    WAKEUP_SCAN = 4,// A message from the gateway to the server containing a wakeup scan result
    SSRB_UPDATE = 83
}
export type ParsedSSGSCPPacket = {
    authSuccess?: true | false;
    packetType?: PacketType;
    encryptionAuthenticationCode?: Buffer | Buffer;
    gatewayUID?: Buffer | Buffer;
    packetID?: number;
    payload?: Buffer | Buffer;
};
/**
 * This class defines various static methods for parsing and constructing
 * SSGSCP packets
 */
export declare class SSGSCP {
    static PACKET_IDENTIFIER: Buffer<ArrayBuffer>;
    /**
    * Packs and encrypts SSGSCP fields into their packet form
    * @param {Object} packet an object containing the SSGSCP packet fields (packetType, gatewayUID, packetID, payload)
    * @param {Buffer} key the key used to encrypt the encrypted portion of the packet
    * @returns {Buffer} a byte array containing the packed SSGSCP packet
    */
    static packSSGSCP(packet: ParsedSSGSCPPacket, key: Buffer | Buffer): Promise<Buffer | null>;
    /**
     * Tries to parses a UDP datagram containing an SSGSCP packet
     * @static
     * @param {Buffer} datagram the datagram containing the SSGSCP packet to parse
     * @param {Buffer} key the key used to decrypt the encrypted portion of the packet
     * @returns {Object} the parsed SSGSCP packet fields or null if the packet cannot be parsed
     */
    static parseSSGSCP(datagram: Buffer, key: Buffer): Promise<ParsedSSGSCPPacket>;
    /**
     * Tries to parse a UDP datagram containing an SSGSCP packet and returns the gateway UID
     * @static
     * @param {Buffer} datagram the datagram containing the SSGSCP packet to parse
     * @returns {Buffer} the gateway UID or null if the packet cannot be parsed
     */
    static parsePacketGatewayUID(datagram: Buffer): Buffer;
    /**
     * Checks if a datagram has a valid SSGSCP packet
     * @static
     * @param {Buffer} datagram a udp datagram
     * @returns {boolean} true if the datagram contains a valid SSGSCP payload, false if not
     */
    static isSSGSCP(datagram: Buffer): boolean;
    static getU16BE(buffer: Buffer): number;
    static setU16BE(value: number): Buffer;
    static errMsg: string;
}
