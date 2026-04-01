/*
 * Lorbrand Sensor Seal Gateway Server
 * Copyright (c) 2023-2026 Lorbrand (Pty) Ltd
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this repository.
 */
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
var __SSGS_DEBUG = false;
var RECV_MSG_FIFO_MAX_LEN = 100;
var SENT_MSG_LIST_MAX_LEN = 100;
var RETRANSMISSION_COUNT_MAX = 10;
var RETRANSMISSION_TIMEOUT_MS = 2000;
var LAST_SEEN_TIMEOUT_MS = 30000; // if a client has not been seen for this long, it is removed from the connectedClients list
var RETRANSMISSIONS_PER_CLIENT_PER_TICK = 10;
var NUM_PACKET_IDS = 65536; // 2^16
var AUTH_CHECK_TIMEOUT_MS = 5000; // if a client is not authorized within this time, it is removed from the checkingAuthorizationFor list
import * as dgram from 'node:dgram';
import * as fs from 'node:fs/promises';
import { SSGSCP } from './ssgscp/ssgscp.js';
import SSProtocols from './ssgscp/ssprotocols.js';
import { assert } from 'node:console';
import { Buffer } from "node:buffer";
var SSGS = /** @class */ (function () {
    /**
     * @constructor
     * @param {number} port - the UDP port number to listen for SSGSCP packets, default is 1818
     * @param {function} onmessage - the callback function to handle incoming messages
     * @param {string} configFilePath - the path to the SSGS configuration file, default is './authorized.json'
     */
    function SSGS(port, onconnection, configFilePath, options) {
        if (port === void 0) { port = 1818; }
        var _this = this;
        this.port = port;
        this.onconnection = onconnection;
        this.onconnectionattempt = function (gatewayUID, remoteAddress, port) { return __awaiter(_this, void 0, void 0, function () { return __generator(this, function (_a) {
            return [2 /*return*/, null];
        }); }); }; // default to rejecting all unauthorized gateways
        this.configFilePath = configFilePath !== null && configFilePath !== void 0 ? configFilePath : './authorized.json';
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
    SSGS.prototype.begin = function () {
        return __awaiter(this, void 0, void 0, function () {
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.loadConfig(this.configFilePath)];
                    case 1:
                        _a.sent();
                        this.socket = dgram.createSocket('udp4');
                        this.socket.on('error', function (err) {
                            console.error('Internal SSGS Server Error:', err.message);
                            _this.socket.close();
                        });
                        this.socket.on('message', function (datagram, rinfo) {
                            _this.process(datagram, rinfo);
                        });
                        this.socket.bind(this.port);
                        setInterval(function () { return _this.tickClients(); }, 200);
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * @method
     * @returns {void}
     * Ticks the connected clients to check for required retransmissions
     * This function should be called periodically, e.g. every 200ms
     * Sends at most 10 retransmissions per client per tick
     */
    SSGS.prototype.tickClients = function () {
        var now = Date.now();
        for (var _i = 0, _a = this.connectedClients; _i < _a.length; _i++) {
            var client = _a[_i];
            // loop over the sent messages and check if any need to be retransmitted, limit to RETRANSMISSIONS_PER_CLIENT_PER_TICK messages per client per tick
            var retransmittedCount = 0;
            for (var _b = 0, _c = client.sentMessages; _b < _c.length; _b++) {
                var sentMessage = _c[_b];
                if (retransmittedCount < RETRANSMISSIONS_PER_CLIENT_PER_TICK && now - sentMessage.timestamp > client.retransmissionTimeout) {
                    // retransmit the message
                    this.socket.send(new Uint8Array(sentMessage.packet), client.sourcePort, client.remoteAddress, function (err) {
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
        for (var i = 0; i < this.checkingAuthorizationFor.length; i++) {
            if (now - this.checkingAuthorizationFor[i].timestamp > AUTH_CHECK_TIMEOUT_MS) {
                this.checkingAuthorizationFor.splice(i, 1);
            }
        }
    };
    /**
     * @method
     * @param {Client} client - the client to remove
     * @returns {void}
     * Removes the client from the connectedClients list and calls the ondisconnect callback function
     */
    SSGS.prototype.removeClient = function (client) {
        var index = this.connectedClients.indexOf(client);
        this.connectedClients.splice(index, 1);
        client.connected = false;
        client.ondisconnect();
    };
    /**
     * @method
     * @param {Client} client - the client to send the message to
     * @param {PacketType} packetType - the type of packet to send
     * @param {Buffer} payload - the payload of the packet
     * @returns {void}
     * Sends a message to the specified client
     * The message is added to the sentMessages list and will be retransmitted if no RCPTOK packet is received within the retransmission timeout
     */
    SSGS.prototype.sendMSG = function (client, packetType, payload) {
        return __awaiter(this, void 0, void 0, function () {
            var packet, packedPacket, resolve, promise, sentMessage;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        packet = {
                            packetType: packetType,
                            gatewayUID: client.gatewayUID,
                            packetID: client.sendPacketID,
                            payload: payload
                        };
                        logIfSSGSDebug('Send to client: ' + JSON.stringify(packet));
                        return [4 /*yield*/, SSGSCP.packSSGSCP(packet, client.key)];
                    case 1:
                        packedPacket = _a.sent();
                        if (!packedPacket) {
                            logIfSSGSDebug('Error: Could not pack packet: ' + SSGSCP.errMsg);
                            return [2 /*return*/];
                        }
                        this.socket.send(new Uint8Array(packedPacket), client.sourcePort, client.remoteAddress, function (err) {
                            if (err) {
                                logIfSSGSDebug('Error: Could not send packet: ' + err);
                            }
                        });
                        promise = new Promise(function (res, rej) {
                            resolve = res;
                        });
                        sentMessage = {
                            packetID: client.sendPacketID,
                            timestamp: Date.now(), // the timestamp of when the message was sent
                            packet: packedPacket,
                            resolve: resolve, // called when the RCPTOK packet is received
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
                        return [4 /*yield*/, promise];
                    case 2: 
                    // return the promise that will be resolved when the RCPTOK packet is received
                    return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * @method
     * @param {Buffer} gatewayUID - the gateway UID to check
     * @returns {boolean} - true if the gateway UID is being checked for authorization, false otherwise
     * Checks if the gateway UID is being checked for authorization
     */
    SSGS.prototype.isCheckingAuthorizationFor = function (gatewayUID) {
        return this.checkingAuthorizationFor.find(function (c) { return SSGS.gatewayUIDsMatch(c.gatewayUID, gatewayUID); }) ? true : false;
    };
    /**
     * @method
     * @param {Buffer} gatewayUID - the gateway UID to set as checking for authorization
     * Sets the gateway UID as checking for authorization
     */
    SSGS.prototype.setCheckingAuthorizationFor = function (gatewayUID) {
        var existing = this.checkingAuthorizationFor.find(function (c) { return SSGS.gatewayUIDsMatch(c.gatewayUID, gatewayUID); });
        if (!existing) {
            this.checkingAuthorizationFor.push({ gatewayUID: gatewayUID, timestamp: Date.now() });
            return;
        }
        existing.timestamp = Date.now();
    };
    /**
     * @method
     * @param {Buffer} gatewayUID - the gateway UID to remove from checking for authorization
     * Removes the gateway UID from checking for authorization
     */
    SSGS.prototype.removeCheckingAuthorizationFor = function (gatewayUID) {
        var index = this.checkingAuthorizationFor.findIndex(function (c) { return SSGS.gatewayUIDsMatch(c.gatewayUID, gatewayUID); });
        if (index != -1) {
            this.checkingAuthorizationFor.splice(index, 1);
        }
    };
    /**
         * @method
         * @param {object} parsedPacket - the parsed packet object from SSGSCP.parseSSGSCP
         * @param {object} rinfo - the remote address information from the UDP socket
         * Processes the incoming packet and calls the onmessage callback function
         */
    SSGS.prototype.process = function (datagram, rinfo) {
        return __awaiter(this, void 0, void 0, function () {
            var gatewayUID, client, callbackProvidedKey, failed, key, myProcessSeq, parsedPacket, newClient_1, isStaleHandler, addressChanged, _i, _a, msg, sentMessage, index, parsedMessage, pingPongSequenceNumber, payload;
            var _this = this;
            var _b, _c;
            return __generator(this, function (_d) {
                switch (_d.label) {
                    case 0:
                        gatewayUID = SSGSCP.parsePacketGatewayUID(datagram);
                        if (!gatewayUID) {
                            logIfSSGSDebug('Error: Could not parse gateway UID from packet');
                            return [2 /*return*/];
                        }
                        client = this.connectedClients.find(function (c) { return SSGS.gatewayUIDsMatch(c.gatewayUID, gatewayUID); });
                        callbackProvidedKey = null;
                        if (!(!client && !this.isCheckingAuthorizationFor(gatewayUID))) return [3 /*break*/, 2];
                        this.setCheckingAuthorizationFor(gatewayUID);
                        if (!!this.isAuthorizedGateway(gatewayUID)) return [3 /*break*/, 2];
                        logIfSSGSDebug('Connecting gateway is not authorized in config, trying onconnectionattempt callback');
                        return [4 /*yield*/, this.onconnectionattempt(gatewayUID, rinfo.address, rinfo.port)];
                    case 1:
                        callbackProvidedKey = _d.sent();
                        failed = false;
                        if (!callbackProvidedKey) {
                            logIfSSGSDebug('onconnectionattempt did not authorize gateway UID: ' + SSGS.uidToString(gatewayUID) + ' from address: ' + rinfo.address);
                            failed = true;
                        }
                        else if (callbackProvidedKey.length != SSGSCP.PSK_LEN_BYTES) {
                            logIfSSGSDebug('onconnectionattempt provided invalid PSK for gateway UID: ' + SSGS.uidToString(gatewayUID));
                            failed = true;
                        }
                        if (failed) {
                            this.sendCONNFAIL(rinfo, gatewayUID);
                            this.removeCheckingAuthorizationFor(gatewayUID);
                            return [2 /*return*/];
                        }
                        logIfSSGSDebug('onconnectionattempt authorized gateway UID: ' + SSGS.uidToString(gatewayUID) + ' from address: ' + rinfo.address);
                        _d.label = 2;
                    case 2:
                        key = (_c = (_b = this.getGatewayKey(gatewayUID)) !== null && _b !== void 0 ? _b : callbackProvidedKey) !== null && _c !== void 0 ? _c : client === null || client === void 0 ? void 0 : client.key;
                        if (!key) {
                            // Only log if we aren't currently checking auth (prevent log spam during auth process)
                            // But if we are here and have no key, we failed.
                            logIfSSGSDebug('Error: Could not find key for gateway UID: ' + SSGS.uidToString(gatewayUID));
                            this.removeCheckingAuthorizationFor(gatewayUID);
                            return [2 /*return*/];
                        }
                        if (client) {
                            client._processSeq = (client._processSeq || 0) + 1;
                            myProcessSeq = client._processSeq;
                        }
                        return [4 /*yield*/, SSGSCP.parseSSGSCP(datagram, key)];
                    case 3:
                        parsedPacket = _d.sent();
                        if (!parsedPacket) { // could not parse the packet
                            logIfSSGSDebug(SSGS.uidToString(gatewayUID) + ': ' + 'Error: Could not parse packet: ' + SSGSCP.errMsg);
                            this.sendCONNFAIL(rinfo, gatewayUID);
                            this.removeCheckingAuthorizationFor(gatewayUID);
                            return [2 /*return*/];
                        }
                        if (!parsedPacket.authSuccess) { // could not authenticate the packet using the key (invalid Message Authentication Code)
                            logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Error: Could not authenticate gateway');
                            this.sendCONNFAIL(rinfo, gatewayUID);
                            this.removeCheckingAuthorizationFor(gatewayUID);
                            return [2 /*return*/];
                        }
                        // if the client was not found initially, check again now.
                        // Another packet might have created the client while we were awaiting parseSSGSCP.
                        if (!client) {
                            client = this.connectedClients.find(function (c) { return SSGS.gatewayUIDsMatch(c.gatewayUID, gatewayUID); });
                        }
                        // if the client is still not found, this is a new connection, so we need to add it to the connectedClients list
                        if (!client) {
                            if (parsedPacket.packetType === 1 /* PacketType.CONN */) {
                                this.sendCONNACPT(rinfo, key, parsedPacket.gatewayUID);
                                newClient_1 = {
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
                                    onmessage: function (parsedMessage) { },
                                    onupdate: function (parsedUpdate) { },
                                    onreconnect: function () { },
                                    ondisconnect: function () { },
                                    send: function (payload) { return __awaiter(_this, void 0, void 0, function () {
                                        return __generator(this, function (_a) {
                                            switch (_a.label) {
                                                case 0: return [4 /*yield*/, this.sendMSG(newClient_1, 20 /* PacketType.MSGCONF */, payload)];
                                                case 1: return [2 /*return*/, _a.sent()];
                                            }
                                        });
                                    }); }
                                };
                                this.connectedClients.push(newClient_1);
                                this.onconnection(newClient_1);
                                // CRITICAL: Now that the client is safely in the list, we remove the protection flag.
                                this.removeCheckingAuthorizationFor(gatewayUID);
                                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'New client connected');
                                return [2 /*return*/];
                            }
                            else {
                                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Error: Client not found in connectedClients and packet type is not CONN');
                                this.sendCONNFAIL(rinfo, parsedPacket.gatewayUID);
                                this.removeCheckingAuthorizationFor(gatewayUID);
                                return [2 /*return*/];
                            }
                        }
                        // If we found the client (either initially or after the race check), clear the auth flag just in case
                        this.removeCheckingAuthorizationFor(gatewayUID);
                        isStaleHandler = myProcessSeq !== undefined && client._processSeq !== myProcessSeq;
                        if (!isStaleHandler) {
                            addressChanged = client.remoteAddress !== rinfo.address || client.sourcePort !== rinfo.port;
                            if (addressChanged && client.sentMessages.length > 0) {
                                // Address changed while messages were pending - those messages were being
                                // retransmitted to the old address and will never be ACK'd. Clear them
                                // and let the application layer re-send if needed.
                                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' +
                                    'Client address changed from ' + client.remoteAddress + ':' + client.sourcePort +
                                    ' to ' + rinfo.address + ':' + rinfo.port +
                                    ', clearing ' + client.sentMessages.length + ' stale pending messages');
                                for (_i = 0, _a = client.sentMessages; _i < _a.length; _i++) {
                                    msg = _a[_i];
                                    msg.resolve(false);
                                }
                                client.sentMessages = [];
                            }
                            client.lastSeen = Date.now();
                            client.remoteAddress = rinfo.address;
                            client.sourcePort = rinfo.port;
                        }
                        else {
                            // Stale handler - a newer packet already updated the address.
                            // Still update lastSeen since this packet proves the client is alive.
                            client.lastSeen = Date.now();
                            logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' +
                                'Skipping address update from stale handler (current: ' + client.remoteAddress + ', stale: ' + rinfo.address + ')');
                        }
                        logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Received packet: ' + JSON.stringify(parsedPacket));
                        switch (parsedPacket.packetType) {
                            // CONNACPT is sent by the server to the client to indicate that the CONN packet was received
                            case 1 /* PacketType.CONN */: {
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
                                setTimeout(function () {
                                    client.onreconnect();
                                }, client.retransmissionTimeout);
                                return [2 /*return*/];
                            }
                            // RCPTOK is sent by the client or server to indicate that a packet was received correctly
                            case 10 /* PacketType.RCPTOK */: {
                                sentMessage = client.sentMessages.find(function (m) { return m.packetID === parsedPacket.packetID; });
                                if (!sentMessage) {
                                    logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Warning: Received RCPTOK for packet ID ' + parsedPacket.packetID + ' but could not find it in sentMessages');
                                    return [2 /*return*/];
                                }
                                // resolve the promise that was returned by the sendMSG function
                                sentMessage.resolve(true);
                                // set the receivedOk flag to true
                                sentMessage.receivedOk = true;
                                index = client.sentMessages.indexOf(sentMessage);
                                client.sentMessages.splice(index, 1);
                                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Received RCPTOK for packet ID ' + parsedPacket.packetID + ', num pending: ' + client.sentMessages.length);
                                return [2 /*return*/];
                            }
                            // MSGSTATUS is sent by the client to the server 
                            case 21 /* PacketType.MSGSTATUS */: {
                                // check for duplicate packet ID in FIFO and ignore if found, otherwise add to FIFO
                                if (client.receivedMessageIDsFIFO.includes(parsedPacket.packetID)) {
                                    logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Warning: Received duplicate MSGSTATUS packet ID ' + parsedPacket.packetID);
                                    // send RCPTOK to client to indicate that we received the packet
                                    this.sendRCPTOK(parsedPacket.packetID, rinfo, key, parsedPacket.gatewayUID);
                                    return [2 /*return*/];
                                }
                                else {
                                    client.receivedMessageIDsFIFO.push(parsedPacket.packetID);
                                    if (client.receivedMessageIDsFIFO.length > RECV_MSG_FIFO_MAX_LEN) {
                                        client.receivedMessageIDsFIFO.shift(); // remove the oldest packet ID, shift left
                                    }
                                }
                                // send RCPTOK to client to indicate that we received the packet
                                this.sendRCPTOK(parsedPacket.packetID, rinfo, key, parsedPacket.gatewayUID);
                                parsedMessage = SSProtocols.parse(parsedPacket);
                                if (!parsedMessage) {
                                    logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Error: Could not parse message: ' + parsedPacket.payload.subarray(0, 100).toString('hex'));
                                    return [2 /*return*/];
                                }
                                // see if its a PING_PONG packet, if so, send a PING_PONG back with the same u8 sequence number in the payload
                                if (parsedMessage.messageType === 1 /* MessageSubtype.PING_PONG */) {
                                    logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Received ping request from gateway ' + SSGS.uidToString(parsedPacket.gatewayUID));
                                    pingPongSequenceNumber = parsedMessage.data;
                                    payload = Buffer.alloc(2);
                                    payload.writeUInt8(1 /* MessageSubtype.PING_PONG */, 0);
                                    payload.writeUInt8(pingPongSequenceNumber, 1);
                                    client.send(payload);
                                    return [2 /*return*/];
                                }
                                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Received message: ' + JSON.stringify(parsedMessage) + ' from gateway ' + SSGS.uidToString(parsedPacket.gatewayUID));
                                client.onmessage(parsedMessage);
                                if (parsedMessage.messageType === 83 /* MessageSubtype.SSRB_UPDATE */) {
                                    client.onupdate(parsedMessage.data);
                                }
                                return [2 /*return*/];
                            }
                            // outbound server->gateway packet types (should never be received by server)
                            case 20 /* PacketType.MSGCONF */: {
                                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Error: Server received outbound server packet: ' + parsedPacket.packetType);
                                return [2 /*return*/];
                            }
                            case 2 /* PacketType.CONNACPT */: {
                                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Error: Server received outbound server packet: ' + parsedPacket.packetType);
                                return [2 /*return*/];
                            }
                            case 3 /* PacketType.CONNFAIL */: {
                                logIfSSGSDebug(SSGS.uidToString(parsedPacket.gatewayUID) + ': ' + 'Error: Server received outbound server packet: ' + parsedPacket.packetType);
                                return [2 /*return*/];
                            }
                            default: {
                                assert(false, 'Software Error: default clause in process() should never be reached');
                            }
                        }
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * @method
     * @param {object} rinfo - the remote address information from the UDP socket
     * Sends a CONNFAIL packet to the remote address to indicate a connection failure
     */
    SSGS.prototype.sendCONNFAIL = function (rinfo, gatewayUID) {
        return __awaiter(this, void 0, void 0, function () {
            var fields, packedPacket;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        fields = {
                            packetType: 3 /* PacketType.CONNFAIL */,
                            packetID: 0,
                            gatewayUID: gatewayUID,
                        };
                        return [4 /*yield*/, SSGSCP.packSSGSCP(fields, Buffer.alloc(32))];
                    case 1:
                        packedPacket = _a.sent();
                        this.socket.send(new Uint8Array(packedPacket), rinfo.port, rinfo.address);
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * @method
     * @param {object} rinfo - the remote address information from the UDP socket
     * Sends a CONNACPT packet to the remote address to indicate a connection success
     * This packet is sent in response to a CONN packet
     */
    SSGS.prototype.sendCONNACPT = function (rinfo, key, gatewayUID) {
        return __awaiter(this, void 0, void 0, function () {
            var fields, packedPacket;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        fields = {
                            packetType: 2 /* PacketType.CONNACPT */,
                            packetID: 0,
                            gatewayUID: gatewayUID,
                        };
                        return [4 /*yield*/, SSGSCP.packSSGSCP(fields, key)];
                    case 1:
                        packedPacket = _a.sent();
                        this.socket.send(new Uint8Array(packedPacket), rinfo.port, rinfo.address);
                        logIfSSGSDebug('Sent CONNACPT to ' + rinfo.address + ':' + rinfo.port);
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * @method
     * @param {number} packetID - the packet ID to send
     * @param {object} rinfo - the remote address information from the UDP socket
     * Sends a RCPTOK packet to the remote address to indicate that the packet with the given packet ID was received correctly
     */
    SSGS.prototype.sendRCPTOK = function (packetID, rinfo, key, gatewayUID) {
        return __awaiter(this, void 0, void 0, function () {
            var fields, packedPacket;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        fields = {
                            packetType: 10 /* PacketType.RCPTOK */,
                            packetID: packetID,
                            gatewayUID: gatewayUID,
                        };
                        return [4 /*yield*/, SSGSCP.packSSGSCP(fields, key)];
                    case 1:
                        packedPacket = _a.sent();
                        this.socket.send(new Uint8Array(packedPacket), rinfo.port, rinfo.address);
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * @method
     * @param {Buffer} gatewayUID - the gateway UID to check
     * @returns {boolean} - true if the gateway UID is authorized, false otherwise
     * Checks if the gateway UID is authorized in the configuration file
     */
    SSGS.prototype.isAuthorizedGateway = function (gatewayUID) {
        var matchingUIDFound = false;
        for (var _i = 0, _a = this.authorizedGateways; _i < _a.length; _i++) {
            var authorizedGateway = _a[_i];
            if (SSGS.gatewayUIDsMatch(authorizedGateway.gatewayUID, gatewayUID))
                matchingUIDFound = true;
        }
        return matchingUIDFound;
    };
    /**
     * @method
     * @param {Buffer} gatewayUID - the gateway UID to check
     * @returns {Buffer | null} - the key for the gateway UID if it is authorized, null otherwise
     * Checks if the gateway UID is authorized in the configuration file and returns the key if it is
     */
    SSGS.prototype.getGatewayKey = function (gatewayUID) {
        for (var _i = 0, _a = this.authorizedGateways; _i < _a.length; _i++) {
            var authorizedGateway = _a[_i];
            if (SSGS.gatewayUIDsMatch(authorizedGateway.gatewayUID, gatewayUID)) {
                return authorizedGateway.key;
            }
        }
        return null;
    };
    /**
     * @method
     * @param {Buffer} gatewayUID - the gateway UID to check
     * @returns {Client | null} - the client object if the gateway UID is connected, null otherwise
     * Checks if the gateway UID is connected and returns the client object if it is
     */
    SSGS.prototype.getClientByGatewayUID = function (gatewayUID) {
        // TODO: optimize this using a binary search hash table
        for (var _i = 0, _a = this.connectedClients; _i < _a.length; _i++) {
            var client = _a[_i];
            if (SSGS.gatewayUIDsMatch(client.gatewayUID, gatewayUID)) {
                return client;
            }
        }
        return null;
    };
    /**
     * @method
     * @param {string} configFilePath - the path to the SSGS configuration file
     * Loads and parses the configuration file and sets up the authorized gateways and key properties
     */
    SSGS.prototype.loadConfig = function (configFilePath) {
        return __awaiter(this, void 0, void 0, function () {
            var _a, _b, _c, e_1, _i, _d, gateway, uid, key;
            return __generator(this, function (_e) {
                switch (_e.label) {
                    case 0:
                        _e.trys.push([0, 2, , 3]);
                        _a = this;
                        _c = (_b = JSON).parse;
                        return [4 /*yield*/, fs.readFile(configFilePath, 'utf8')];
                    case 1:
                        _a.configFile = _c.apply(_b, [_e.sent()]);
                        return [3 /*break*/, 3];
                    case 2:
                        e_1 = _e.sent();
                        if (e_1.code === 'ENOENT') {
                            console.log('SSGS: Config file not found (' + configFilePath + '), starting with no pre-authorized gateways. Use onconnectionattempt callback to authorize dynamically.');
                            this.configFile = { key: '', authorized_gateways: [] };
                            this.authorizedGateways = [];
                            return [2 /*return*/];
                        }
                        throw e_1; // re-throw JSON parse errors or permission errors
                    case 3:
                        this.authorizedGateways = [];
                        // parse the authorized gateways
                        for (_i = 0, _d = this.configFile.authorized_gateways; _i < _d.length; _i++) {
                            gateway = _d[_i];
                            uid = Buffer.from(gateway.uid.replace(/\s/g, ''), 'hex');
                            if (uid.length != 4)
                                throw new Error('SSGS Config: uid length must be 4');
                            key = Buffer.from(gateway.key.replace(/\s/g, ''), 'hex');
                            if (key.length != 32)
                                throw new Error('SSGS Config: gateway key length must be 32');
                            this.authorizedGateways.push({ gatewayUID: uid, key: key });
                        }
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * @method
     * @static
     * @param {Buffer} gatewayUID1 - the first gateway UID to compare
     * @param {Buffer} gatewayUID2 - the second gateway UID to compare
     * @returns {boolean} - true if the gateway UIDs match, false otherwise
     * Compares two gateway UIDs and returns true if they match, false otherwise
     * Gateway UIDs are 4 bytes long
     */
    SSGS.gatewayUIDsMatch = function (gatewayUID1, gatewayUID2) {
        if (!gatewayUID1 || !gatewayUID2) // should not be null or undefined
            return false;
        if (gatewayUID1.length != 4 || gatewayUID2.length != 4) // should be 4 bytes long
            return false;
        // compare each byte
        for (var i = 0; i < 4; i++) {
            if (gatewayUID1[i] != gatewayUID2[i])
                return false;
        }
        return true;
    };
    /**
     * @method
     * @static
     * @param {Buffer} uid - the UID to convert to a string
     * @returns {string} - the UID as a string
     * Converts a UID to a string
     */
    SSGS.uidToString = function (uid) {
        if (!uid || uid.length != 4)
            return 'Invalid UID';
        // UID should be outputted as [ab cd ef 12]
        var uidString = '[';
        for (var i = 0; i < uid.length; i++) {
            uidString += uid[i].toString(16).padStart(2, '0');
            if (i != uid.length - 1)
                uidString += ' ';
        }
        uidString += ']';
        return uidString;
    };
    return SSGS;
}());
;
export default SSGS;
/**
 * @function
 * @param {string} info - the debug information to log
 * Logs the debug information if __SSGS_DEBUG is true
 */
function logIfSSGSDebug(info) {
    if (__SSGS_DEBUG)
        console.log('SSGS Debug Info:', info);
}
