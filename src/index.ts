/*

    Lorbrand Sensor Seal Gateway Server
    --------------------------------------------------------------

    Copyright (C) 2023-2026 Lorbrand (Pty) Ltd

    https://github.com/Lorbrand/SSGS-Node#readme

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

let __SSGS_DEBUG: boolean = false;

const RECV_MSG_FIFO_MAX_LEN = 100;
const SENT_MSG_LIST_MAX_LEN = 100;
const RETRANSMISSION_COUNT_MAX = 10;
const RETRANSMISSION_TIMEOUT_MS = 2000;
const LAST_SEEN_TIMEOUT_MS = 30000; // if a client has not been seen for this long, it is removed from the connectedClients list
const RETRANSMISSIONS_PER_CLIENT_PER_TICK = 10;
const NUM_PACKET_IDS = 65536; // 2^16
const AUTH_CHECK_TIMEOUT_MS = 5000; // if a client is not authorized within this time, it is removed from the checkingAuthorizationFor list

import * as dgram from 'node:dgram';
import * as fs from 'node:fs/promises';

import { SSGSCP } from './ssgscp/ssgscp.js';
import { ParsedSSGSCPPacket } from './ssgscp/ssgscp.js';
import { PacketType } from './ssgscp/ssgscp.js';

import { MessageSubtype } from './ssgscp/ssgscp.js';
import { SensorSealUpdate } from './ssgscp/ssprotocols.js';
import { ParsedMessage } from './ssgscp/ssprotocols.js';
import SSProtocols from './ssgscp/ssprotocols.js';

import { assert } from 'node:console';
import { Buffer } from "node:buffer";


type ConfigFile = {
    key: string;
    authorized_gateways: Array<{ uid: string, key: string }>;
};

type AuthorizedGateway = {
    gatewayUID: Buffer;
    key: Buffer;
};

type SentMessage = {
    packetID: number; // the packet ID of the message
    timestamp: number; // the timestamp of when the message was sent
    packet: Buffer; // the packed SSGSCP packet
    resolve: (receivedOk: boolean) => void; // the resolve function of the promise
    receivedOk: boolean; // whether the message was received ok
    retransmissionCount: number; // the number of times the message has been retransmitted
};

export type Client = { // the client state machine
    gatewayUID: Buffer; // the client (gateway) UID
    sourcePort: number; // the UDP port number the client is sending from (ephemeral port)
    remoteAddress: string; // the IP address of the client
    lastSeen: number; // the timestamp of the last time the client sent a message
    connected: boolean; // whether the client is connected and authenticated
    sendPacketID: number; // the packet ID of the next message to send to the client
    retransmissionTimeout: number; // the retransmission timeout in milliseconds
    sentMessages: Array<SentMessage>; // the list of sent messages
    receivedMessageIDsFIFO: Array<number>; // the list of received message IDs, needed for duplicate detection, max length is RECV_MSG_FIFO_MAX_LEN
    key: Buffer; // the encryption key
    _processSeq: number; // monotonic counter to detect stale async handlers after await points
    onmessage: (update: ParsedMessage) => void; // the callback function to handle incoming messages from the gateway
    onupdate: (update: SensorSealUpdate) => void; // the callback function to handle incoming Sensor Seal updates
    onreconnect: () => void; // the callback function to handle a client reconnecting
    ondisconnect: () => void; // the callback function to handle a client disconnecting
    /**
     * @method
     * @param {Buffer} payload - the payload to send to the client
     * @returns {Promise<boolean>} - whether the message was received ok
     * Sends a MSGCONF packet to the client and returns a promise resolving to whether the message was 
     * received ok or false after it has been retransmitted RETRANSMISSION_COUNT_MAX times
     */
    send: (payload: Buffer) => Promise<boolean>; // the function to send a CONF packet to the client
}

type ssgsOptions = {
    debug?: boolean;
};

class SSGS {
    /**
     * @param {Client} client - the new authorized client that has connected
     * The callback function that is called when a new client (gateway) has connected and is authenticated
     */
    onconnection: (client: Client) => void;

    /**
     * @param {Buffer} gatewayUID - the UID of the gateway
     * @param {string} remoteAddress - the IP address of the gateway that is attempting to connect
     * @param {number} port - the UDP source port number of the gateway that is attempting to connect
     * @returns {Buffer | null} - the key of the gateway if it should be authorized, null otherwise
     * The callback function that is called when an unauthorized gateway (not in config file) attempts to connect
     * Return the key of the gateway if it should be authorized, null otherwise
     * If this function is not set, all unauthorized gateways will be rejected
     */
    onconnectionattempt: (gatewayUID: Buffer, remoteAddress: string, port: number) => Promise<Buffer | null>;

    port: number; // the UDP port number to listen for SSGSCP packets
    configFilePath: string; // the path to the SSGS configuration file
    socket: dgram.Socket; // the UDP socket
    configFile: ConfigFile; // the configuration file object
    authorizedGateways: Array<AuthorizedGateway>; // the list of authorized gateways
    connectedClients: Array<Client>; // the list of connected clients
    checkingAuthorizationFor: Array<{ gatewayUID: Buffer, timestamp: number }>; // the list of gateways that are being checked for authorization

    /**
     * @constructor
     * @param {number} port - the UDP port number to listen for SSGSCP packets, default is 1818
     * @param {function} onmessage - the callback function to handle incoming messages
     * @param {string} configFilePath - the path to the SSGS configuration file, default is './authorized.json'
     */
    constructor(port: number = 1818, onconnection: (client: Client) => void, configFilePath?: string, options?: ssgsOptions) {
        this.port = port;
        this.onconnection = onconnection;
        this.onconnectionattempt = async (gatewayUID, remoteAddress, port) => { return null; }; // default to rejecting all unauthorized gateways
        this.configFilePath = configFilePath ?? './authorized.json';
        this.socket = null;
        this.configFile = null;
        this.authorizedGateways = [];
        this.connectedClients = [];
        this.checkingAuthorizationFor = [];

        if (options && options.debug) {
            console.log('SSGS: Debug mode enabled');
            __SSGS_DEBUG = true;
        }

        this.begin();
    }

    /**
     * @method
     * @async
     * Starts the SSGS server by loading the configuration file and listening for incoming messages on the specified UDP port
     */
    async begin() {
        await this.loadConfig(this.configFilePath);
        this.socket = dgram.createSocket('udp4');

        this.socket.on('error', (err) => {
            console.error('Internal SSGS Server Error:', err.message);
            this.socket.close();
        });

        this.socket.on('message', (datagram: Buffer, rinfo: dgram.RemoteInfo) => {
            this.process(datagram, rinfo);
        });

        this.socket.bind(this.port);
        setInterval(() => this.tickClients(), 200);
    }

    /**
     * @method
     * @returns {void}
     * Ticks the connected clients to check for required retransmissions
     * This function should be called periodically, e.g. every 200ms
     * Sends at most 10 retransmissions per client per tick
     */
    tickClients() {
        const now = Date.now();

        for (const client of this.connectedClients) {
            // loop over the sent messages and check if any need to be retransmitted, limit to RETRANSMISSIONS_PER_CLIENT_PER_TICK messages per client per tick
            let retransmittedCount = 0;

            for (const sentMessage of client.sentMessages) {
                if (retransmittedCount < RETRANSMISSIONS_PER_CLIENT_PER_TICK && now - sentMessage.timestamp > client.retransmissionTimeout) {
                    // retransmit the message
                    this.socket.send(new Uint8Array(sentMessage.packet), client.sourcePort, client.remoteAddress, (err) => {
                        if (err)
                            logIfSSGSDebug('Error: Could not send packet: ' + err);
                    });
                    logIfSSGSDebug('Retransmitting packet to client ' + SSGS.uidToString(client.gatewayUID) + ': ' + sentMessage.packetID + ', num pending: ' + client.sentMessages.length);
                    sentMessage.timestamp = Date.now();
                    sentMessage.retransmissionCount++;

                    // if the message has been retransmitted more than RETRANSMISSION_COUNT_MAX times, remove it from the list and resolve the promise to false
                    if (sentMessage.retransmissionCount > RETRANSMISSION_COUNT_MAX) {
                        sentMessage.resolve(false);
                        client.sentMessages.splice(client.sentMessages.indexOf(sentMessage), 1);
                    }

                    retransmittedCount++;
                }
            }

            // remove the client if it has not been seen for LAST_SEEN_TIMEOUT_MS
            if (now - client.lastSeen > LAST_SEEN_TIMEOUT_MS) {
                this.removeClient(client);
                logIfSSGSDebug('Client ' + SSGS.uidToString(client.gatewayUID) + ' removed due to inactivity');
            }

        }

        for (let i = 0; i < this.checkingAuthorizationFor.length; i++) {
            if (now - this.checkingAuthorizationFor[i].timestamp > AUTH_CHECK_TIMEOUT_MS) {
                this.checkingAuthorizationFor.splice(i, 1);
            }
        }

    }

    /**
     * @method
     * @param {Client} client - the client to remove
     * @returns {void}
     * Removes the client from the connectedClients list and calls the ondisconnect callback function
     */
    removeClient(client: Client) {
        const index = this.connectedClients.indexOf(client);
        this.connectedClients.splice(index, 1);
        client.connected = false;
        client.ondisconnect();
    }


    /**
     * @method
     * @param {Client} client - the client to send the message to
     * @param {PacketType} packetType - the type of packet to send
     * @param {Buffer} payload - the payload of the packet
     * @returns {void}
     * Sends a message to the specified client
     * The message is added to the sentMessages list and will be retransmitted if no RCPTOK packet is received within the retransmission timeout
     */
    async sendMSG(client: Client, packetType: PacketType, payload: Buffer): Promise<boolean> {
        const packet: ParsedSSGSCPPacket = {
            packetType,
            gatewayUID: client.gatewayUID,
            packetID: client.sendPacketID,
            payload
        };

        logIfSSGSDebug('Send to client: ' + JSON.stringify(packet));

        const packedPacket = await SSGSCP.packSSGSCP(packet, client.key);
        if (!packedPacket) {
            logIfSSGSDebug('Error: Could not pack packet: ' + SSGSCP.errMsg);
            return;
        }

        this.socket.send(new Uint8Array(packedPacket), client.sourcePort, client.remoteAddress, (err) => {
            if (err) {
                logIfSSGSDebug('Error: Could not send packet: ' + err);
            }
        });

        // create a promise that will be resolved when the RCPTOK packet is received
        let resolve: (receivedOk: boolean) => void;
        const promise = new Promise<boolean>((res, rej) => {
            resolve = res;
        });

        // add the sent message to the sentMessages list
        const sentMessage: SentMessage = {
            packetID: client.sendPacketID,
            timestamp: Date.now(), // the timestamp of when the message was sent
            packet: packedPacket,
            resolve, // called when the RCPTOK packet is received
            receivedOk: false, // set to true when the RCPTOK packet is received
            retransmissionCount: 0 // the number of times the message has been retransmitted
        };

        client.sentMessages.push(sentMessage);

        // increment the packet ID
        client.sendPacketID = (client.sendPacketID + 1) % NUM_PACKET_IDS;

        // if the sentMessages list is too long, remove the oldest message
        // if (client.sentMessages.length > SENT_MSG_LIST_MAX_LEN) {
        //     client.sentMessages.shift();
        // }

        // Workaround: instead, if the sentMessages list is too long, remove the client so that it can reconnect
        // if the number of sent messages is equal to SENT_MSG_LIST_MAX_LEN, this indicates there is a serious
        // problem with the client or network (high latency), so we remove the client to try and resolve the issue
        // This needs to be addressed properly in the future
        if (client.sentMessages.length > SENT_MSG_LIST_MAX_LEN) {
            this.removeClient(client);
            logIfSSGSDebug('Client ' + SSGS.uidToString(client.gatewayUID) + ' removed due to too many pending messages. It should reconnect after some time.');
        }

        // return the promise that will be resolved when the RCPTOK packet is received
        return await promise;
    }

    /**
     * @method
     * @param {Buffer} gatewayUID - the gateway UID to check
     * @returns {boolean} - true if the gateway UID is being checked for authorization, false otherwise
     * Checks if the gateway UID is being checked for authorization
     */
    isCheckingAuthorizationFor(gatewayUID: Buffer): boolean {
        return this.checkingAuthorizationFor.find((c) => SSGS.gatewayUIDsMatch(c.gatewayUID, gatewayUID)) ? true : false;
    }

    /**
     * @method
     * @param {Buffer} gatewayUID - the gateway UID to set as checking for authorization
     * Sets the gateway UID as checking for authorization
     */
    setCheckingAuthorizationFor(gatewayUID: Buffer) {
        const existing = this.checkingAuthorizationFor.find((c) => SSGS.gatewayUIDsMatch(c.gatewayUID, gatewayUID));
        if (!existing) {
            this.checkingAuthorizationFor.push({ gatewayUID, timestamp: Date.now() });
            return;
        }

        existing.timestamp = Date.now();
    }

    /**
     * @method
     * @param {Buffer} gatewayUID - the gateway UID to remove from checking for authorization
     * Removes the gateway UID from checking for authorization
     */
    removeCheckingAuthorizationFor(gatewayUID: Buffer) {
        const index = this.checkingAuthorizationFor.findIndex((c) => SSGS.gatewayUIDsMatch(c.gatewayUID, gatewayUID));
        if (index != -1) {
            this.checkingAuthorizationFor.splice(index, 1);
        }
    }

/**
     * @method
     * @param {object} parsedPacket - the parsed packet object from SSGSCP.parseSSGSCP
     * @param {object} rinfo - the remote address information from the UDP socket
     * Processes the incoming packet and calls the onmessage callback function
     */
    async process(datagram: Buffer, rinfo: dgram.RemoteInfo) {

        const gatewayUID = SSGSCP.parsePacketGatewayUID(datagram);
        if (!gatewayUID) {
            logIfSSGSDebug('Error: Could not parse gateway UID from packet');
            return;
        }

        // try find the Client state machine for this gateway client (in connectedClients)
        let client = this.connectedClients.find((c) => SSGS.gatewayUIDsMatch(c.gatewayUID, gatewayUID));

        let callbackProvidedKey: Buffer | null = null;

        if (!client && !this.isCheckingAuthorizationFor(gatewayUID)) { // client not found, check if gateway is authorized
            this.setCheckingAuthorizationFor(gatewayUID);
            
            // Note: We keep the CheckingAuthorizationFor flag active until the very end of the connection process
            // to prevent race conditions where multiple CONN packets try to authorize simultaneously.

            if (!this.isAuthorizedGateway(gatewayUID)) {
                logIfSSGSDebug('Connecting gateway is not authorized in config, trying onconnectionattempt callback');

                callbackProvidedKey = await this.onconnectionattempt(gatewayUID, rinfo.address, rinfo.port);
                
                if (!callbackProvidedKey) {
                    logIfSSGSDebug('onconnectionattempt did not authorize gateway UID: ' + SSGS.uidToString(gatewayUID) + ' from address: ' + rinfo.address);
                    this.sendCONNFAIL(rinfo, gatewayUID);
                    this.removeCheckingAuthorizationFor(gatewayUID);
                    return;
                }

                logIfSSGSDebug('onconnectionattempt authorized gateway UID: ' + SSGS.uidToString(gatewayUID) + ' from address: ' + rinfo.address);
                // CRITICAL: We do NOT removeCheckingAuthorizationFor here. We wait until the client is added.
            }
        }

        // first try get the key from the config file, if not found, try get it from the callback, if not found, try get it from the client object (if it exists)
        const key = this.getGatewayKey(gatewayUID) ?? callbackProvidedKey ?? client?.key;
        if (!key) {
            // Only log if we aren't currently checking auth (prevent log spam during auth process)
            // But if we are here and have no key, we failed.
            logIfSSGSDebug('Error: Could not find key for gateway UID: ' + SSGS.uidToString(gatewayUID));
            this.removeCheckingAuthorizationFor(gatewayUID);
            return;
        }

        // Increment the process sequence counter BEFORE the async gap. After the await,
        // we check if our seq still matches - if not, a newer packet has arrived and we
        // must not overwrite the client's address with our (now stale) rinfo.
        // This prevents the IP clobbering bug where a failover IP change causes the
        // server to send retransmissions to the old IP indefinitely.
        let myProcessSeq: number | undefined;
        if (client) {
            client._processSeq = (client._processSeq || 0) + 1;
            myProcessSeq = client._processSeq;
        }

        // try parse the packet using the key
        // This is ASYNC - the event loop yields here, so other packet handlers can run.
        const parsedPacket = await SSGSCP.parseSSGSCP(datagram, key);

        if (!parsedPacket) { // could not parse the packet
            logIfSSGSDebug(SSGS.uidToString(gatewayUID) + ': ' + 'Error: Could not parse packet: ' + SSGSCP.errMsg);
            this.sendCONNFAIL(rinfo, gatewayUID);
            this.removeCheckingAuthorizationFor(gatewayUID);
            return;
        }

        if (!parsedPacket.authSuccess) { // could not authenticate the packet using the key (invalid Message Authentication Code)
            logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Error: Could not authenticate gateway');
            this.sendCONNFAIL(rinfo, gatewayUID);
            this.removeCheckingAuthorizationFor(gatewayUID);
            return;
        }

        // if the client was not found initially, check again now.
        // Another packet might have created the client while we were awaiting parseSSGSCP.
        if (!client) {
             client = this.connectedClients.find((c) => SSGS.gatewayUIDsMatch(c.gatewayUID, gatewayUID));
        }

        // if the client is still not found, this is a new connection, so we need to add it to the connectedClients list
        if (!client) {
            if (parsedPacket.packetType === PacketType.CONN) {
                this.sendCONNACPT(rinfo, key, parsedPacket.gatewayUID);
                const newClient: Client = {
                    gatewayUID: parsedPacket.gatewayUID,
                    sourcePort: rinfo.port,
                    remoteAddress: rinfo.address,
                    lastSeen: Date.now(),
                    connected: true,
                    sendPacketID: 0,
                    retransmissionTimeout: RETRANSMISSION_TIMEOUT_MS,
                    sentMessages: [],
                    receivedMessageIDsFIFO: [],
                    key: key,
                    _processSeq: 0,
                    onmessage: (parsedMessage: ParsedMessage) => { },
                    onupdate: (parsedUpdate: SensorSealUpdate) => { },
                    onreconnect: () => { },
                    ondisconnect: () => { },
                    send: async (payload: Buffer) => {
                        return await this.sendMSG(newClient, PacketType.MSGCONF, payload);
                    }
                };

                this.connectedClients.push(newClient);
                this.onconnection(newClient);
                
                // CRITICAL: Now that the client is safely in the list, we remove the protection flag.
                this.removeCheckingAuthorizationFor(gatewayUID);
                
                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'New client connected');
                return;
            } else {
                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Error: Client not found in connectedClients and packet type is not CONN');
                this.sendCONNFAIL(rinfo, parsedPacket.gatewayUID);
                this.removeCheckingAuthorizationFor(gatewayUID);
                return;
            }
        }
        
        // If we found the client (either initially or after the race check), clear the auth flag just in case
        this.removeCheckingAuthorizationFor(gatewayUID);

        // Only update the client's address if no newer packet handler has run since we
        // started our await. This prevents stale handlers (e.g. from a previous IP before
        // a failover) from overwriting the address that a newer handler already set.
        const isStaleHandler = myProcessSeq !== undefined && client._processSeq !== myProcessSeq;

        if (!isStaleHandler) {
            // Check if the client's address/port actually changed
            const addressChanged = client.remoteAddress !== rinfo.address || client.sourcePort !== rinfo.port;

            if (addressChanged && client.sentMessages.length > 0) {
                // Address changed while messages were pending - those messages were being
                // retransmitted to the old address and will never be ACK'd. Clear them
                // and let the application layer re-send if needed.
                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' +
                    'Client address changed from ' + client.remoteAddress + ':' + client.sourcePort +
                    ' to ' + rinfo.address + ':' + rinfo.port +
                    ', clearing ' + client.sentMessages.length + ' stale pending messages');
                for (const msg of client.sentMessages) {
                    msg.resolve(false);
                }
                client.sentMessages = [];
            }

            client.lastSeen = Date.now();
            client.remoteAddress = rinfo.address;
            client.sourcePort = rinfo.port;
        } else {
            // Stale handler - a newer packet already updated the address.
            // Still update lastSeen since this packet proves the client is alive.
            client.lastSeen = Date.now();
            logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' +
                'Skipping address update from stale handler (current: ' + client.remoteAddress + ', stale: ' + rinfo.address + ')');
        }

        logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Received packet: ' + JSON.stringify(parsedPacket));

        switch (parsedPacket.packetType) {
            // CONNACPT is sent by the server to the client to indicate that the CONN packet was received
            case PacketType.CONN: {
                // we already have a client state machine but receivinng this could mean that the client restarted,
                // so we need to reset part of the state machine
                client.sendPacketID = 0;
                client.retransmissionTimeout = RETRANSMISSION_TIMEOUT_MS; // assume RTT is 2000 ms for now
                client.sentMessages = [];
                client.receivedMessageIDsFIFO = [];
                client.remoteAddress = rinfo.address;
                client.sourcePort = rinfo.port;

                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Warning: Received CONN packet from already connected client, assuming client restarted');

                // send CONNACPT to client to indicate that we received the packet
                this.sendCONNACPT(rinfo, key, parsedPacket.gatewayUID);

                setTimeout(() => {
                    client.onreconnect();
                }, client.retransmissionTimeout);

                return;
            }

            // RCPTOK is sent by the client or server to indicate that a packet was received correctly
            case PacketType.RCPTOK: {
                // packet we sent was received correctly by the client, so we can remove it from the sentMessages list
                const sentMessage = client.sentMessages.find((m) => m.packetID === parsedPacket.packetID);

                if (!sentMessage) {
                    logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Warning: Received RCPTOK for packet ID ' + parsedPacket.packetID + ' but could not find it in sentMessages');
                    return;
                }

                // resolve the promise that was returned by the sendMSG function
                sentMessage.resolve(true);

                // set the receivedOk flag to true
                sentMessage.receivedOk = true;

                const index = client.sentMessages.indexOf(sentMessage);
                client.sentMessages.splice(index, 1);

                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Received RCPTOK for packet ID ' + parsedPacket.packetID + ', num pending: ' + client.sentMessages.length);


                return;
            }

            // MSGSTATUS is sent by the client to the server 
            case PacketType.MSGSTATUS: {
                // check for duplicate packet ID in FIFO and ignore if found, otherwise add to FIFO
                if (client.receivedMessageIDsFIFO.includes(parsedPacket.packetID)) {
                    logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Warning: Received duplicate MSGSTATUS packet ID ' + parsedPacket.packetID);

                    // send RCPTOK to client to indicate that we received the packet
                    this.sendRCPTOK(parsedPacket.packetID, rinfo, key, parsedPacket.gatewayUID);

                    return;
                } else {
                    client.receivedMessageIDsFIFO.push(parsedPacket.packetID);
                    if (client.receivedMessageIDsFIFO.length > RECV_MSG_FIFO_MAX_LEN) {
                        client.receivedMessageIDsFIFO.shift(); // remove the oldest packet ID, shift left
                    }
                }

                // send RCPTOK to client to indicate that we received the packet
                this.sendRCPTOK(parsedPacket.packetID, rinfo, key, parsedPacket.gatewayUID);

                // try parse from a variety of SSGSCP MSG payload formats
                const parsedMessage = SSProtocols.parse(parsedPacket);

                if (!parsedMessage) {
                    logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Error: Could not parse message: ' + parsedPacket.payload.subarray(0, 100).toString('hex'));
                    return;
                }

                // see if its a PING_PONG packet, if so, send a PING_PONG back with the same u8 sequence number in the payload
                if (parsedMessage.messageType === MessageSubtype.PING_PONG) {
                    logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Received ping request from gateway ' + SSGS.uidToString(parsedPacket.gatewayUID));
                    const pingPongSequenceNumber = parsedMessage.data as number;
                    const payload = Buffer.alloc(2);
                    payload.writeUInt8(MessageSubtype.PING_PONG, 0);
                    payload.writeUInt8(pingPongSequenceNumber, 1);
                    client.send(payload);
                    return;
                }
                
                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Received message: ' + JSON.stringify(parsedMessage) + ' from gateway ' + SSGS.uidToString(parsedPacket.gatewayUID));
                client.onmessage(parsedMessage);

                if (parsedMessage.messageType === MessageSubtype.SSRB_UPDATE) {
                    client.onupdate(<SensorSealUpdate>parsedMessage.data);
                }

                return;
            }


            // outbound server->gateway packet types (should never be received by server)
            case PacketType.MSGCONF: {
                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Error: Server received outbound server packet: ' + parsedPacket.packetType);
                return;
            }
            case PacketType.CONNACPT: {
                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Error: Server received outbound server packet: ' + parsedPacket.packetType);
                return;
            }
            case PacketType.CONNFAIL: {
                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Error: Server received outbound server packet: ' + parsedPacket.packetType);
                return;
            }
            default: {
                assert(false, 'Software Error: default clause in process() should never be reached');
            }
        }
    }

    /**
     * @method
     * @param {object} rinfo - the remote address information from the UDP socket
     * Sends a CONNFAIL packet to the remote address to indicate a connection failure
     */
    async sendCONNFAIL(rinfo: dgram.RemoteInfo, gatewayUID: Buffer) {
        const fields: ParsedSSGSCPPacket = {
            packetType: PacketType.CONNFAIL,
            packetID: 0,
            gatewayUID: gatewayUID,
        };

        // CONNFAIL packets are not encrypted

        const packedPacket = await SSGSCP.packSSGSCP(fields, Buffer.alloc(32));
        this.socket.send(new Uint8Array(packedPacket), rinfo.port, rinfo.address);
    }

    /**
     * @method
     * @param {object} rinfo - the remote address information from the UDP socket
     * Sends a CONNACPT packet to the remote address to indicate a connection success
     * This packet is sent in response to a CONN packet
     */
    async sendCONNACPT(rinfo: dgram.RemoteInfo, key: Buffer, gatewayUID: Buffer) {
        const fields: ParsedSSGSCPPacket = {
            packetType: PacketType.CONNACPT,
            packetID: 0,
            gatewayUID: gatewayUID,
        };

        const packedPacket = await SSGSCP.packSSGSCP(fields, key);
        this.socket.send(new Uint8Array(packedPacket), rinfo.port, rinfo.address);
        logIfSSGSDebug('Sent CONNACPT to ' + rinfo.address + ':' + rinfo.port);
    }

    /**
     * @method
     * @param {number} packetID - the packet ID to send
     * @param {object} rinfo - the remote address information from the UDP socket
     * Sends a RCPTOK packet to the remote address to indicate that the packet with the given packet ID was received correctly
     */
    async sendRCPTOK(packetID: number, rinfo: dgram.RemoteInfo, key: Buffer, gatewayUID: Buffer) {
        const fields: ParsedSSGSCPPacket = {
            packetType: PacketType.RCPTOK,
            packetID: packetID,
            gatewayUID: gatewayUID,
        };

        const packedPacket = await SSGSCP.packSSGSCP(fields, key);
        this.socket.send(new Uint8Array(packedPacket), rinfo.port, rinfo.address);
    }

    /**
     * @method
     * @param {Buffer} gatewayUID - the gateway UID to check
     * @returns {boolean} - true if the gateway UID is authorized, false otherwise
     * Checks if the gateway UID is authorized in the configuration file
     */
    isAuthorizedGateway(gatewayUID: Buffer): boolean {
        let matchingUIDFound = false;
        for (const authorizedGateway of this.authorizedGateways) {
            if (SSGS.gatewayUIDsMatch(authorizedGateway.gatewayUID, gatewayUID))
                matchingUIDFound = true;
        }

        return matchingUIDFound;
    }

    /**
     * @method
     * @param {Buffer} gatewayUID - the gateway UID to check
     * @returns {Buffer | null} - the key for the gateway UID if it is authorized, null otherwise
     * Checks if the gateway UID is authorized in the configuration file and returns the key if it is
     */
    getGatewayKey(gatewayUID: Buffer): Buffer | null {
        for (const authorizedGateway of this.authorizedGateways) {
            if (SSGS.gatewayUIDsMatch(authorizedGateway.gatewayUID, gatewayUID)) {
                return authorizedGateway.key;
            }
        }

        return null;
    }

    /**
     * @method
     * @param {Buffer} gatewayUID - the gateway UID to check
     * @returns {Client | null} - the client object if the gateway UID is connected, null otherwise
     * Checks if the gateway UID is connected and returns the client object if it is
     */
    getClientByGatewayUID(gatewayUID: Buffer): Client | null {
        // TODO: optimize this using a binary search hash table
        for (const client of this.connectedClients) {
            if (SSGS.gatewayUIDsMatch(client.gatewayUID, gatewayUID)) {
                return client;
            }
        }

        return null;
    }

    /**
     * @method
     * @param {string} configFilePath - the path to the SSGS configuration file 
     * Loads and parses the configuration file and sets up the authorized gateways and key properties
     */
    async loadConfig(configFilePath: string) {
        // load the config file - if it doesn't exist, start with no pre-authorized gateways
        // (connections can still be authorized dynamically via the onconnectionattempt callback)
        try {
            this.configFile = JSON.parse(await fs.readFile(configFilePath, 'utf8'));
        } catch (e: any) {
            if (e.code === 'ENOENT') {
                console.log('SSGS: Config file not found (' + configFilePath + '), starting with no pre-authorized gateways. Use onconnectionattempt callback to authorize dynamically.');
                this.configFile = { key: '', authorized_gateways: [] };
                this.authorizedGateways = [];
                return;
            }
            throw e; // re-throw JSON parse errors or permission errors
        }
        this.authorizedGateways = [];

        // parse the authorized gateways
        for (const gateway of this.configFile.authorized_gateways) {
            // Parse the hex-formatted string and obtain a byte array
            const uid = Buffer.from(gateway.uid.replace(/\s/g, ''), 'hex');

            if (uid.length != 4)
                throw new Error('SSGS Config: uid length must be 4');

            // Parse the hex-formatted key string (256-bit key) and obtain a byte array
            const key = Buffer.from(gateway.key.replace(/\s/g, ''), 'hex');

            if (key.length != 32)
                throw new Error('SSGS Config: gateway key length must be 32');

            this.authorizedGateways.push({ gatewayUID: uid, key: key });
        }
    }


    /**
     * @method
     * @static
     * @param {Buffer} gatewayUID1 - the first gateway UID to compare
     * @param {Buffer} gatewayUID2 - the second gateway UID to compare
     * @returns {boolean} - true if the gateway UIDs match, false otherwise
     * Compares two gateway UIDs and returns true if they match, false otherwise
     * Gateway UIDs are 4 bytes long
     */
    static gatewayUIDsMatch(gatewayUID1: Buffer, gatewayUID2: Buffer): boolean {
        if (!gatewayUID1 || !gatewayUID2) // should not be null or undefined
            return false;

        if (gatewayUID1.length != 4 || gatewayUID2.length != 4) // should be 4 bytes long
            return false;

        // compare each byte
        for (let i = 0; i < 4; i++) {
            if (gatewayUID1[i] != gatewayUID2[i])
                return false;
        }

        return true;
    }

    /**
     * @method
     * @static
     * @param {Buffer} uid - the UID to convert to a string
     * @returns {string} - the UID as a string
     * Converts a UID to a string
     */
    static uidToString(uid: Buffer): string {
        if (!uid || uid.length != 4)
            return 'Invalid UID';

        // UID should be outputted as [ab cd ef 12]
        let uidString = '[';
        for (let i = 0; i < uid.length; i++) {
            uidString += uid[i].toString(16).padStart(2, '0');
            if (i != uid.length - 1)
                uidString += ' ';
        }
        uidString += ']';

        return uidString;
    }
};

export default SSGS;
export { MessageSubtype };
export { SensorSealUpdate };
export { ParsedMessage };


/**
 * @function
 * @param {string} info - the debug information to log 
 * Logs the debug information if __SSGS_DEBUG is true
 */
function logIfSSGSDebug(info: any) {
    if (__SSGS_DEBUG)
        console.log('SSGS Debug Info:', info);
}
