/*

    Lorbrand Sensor Seal Gateway Server
    --------------------------------------------------------------

    Copyright (C) 2023 Lorbrand (Pty) Ltd

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
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
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
import * as dgram from 'node:dgram';
import * as fs from 'node:fs/promises';
import { SSGSCP } from './ssgscp/ssgscp.js';
import SSProtocols from './ssprotocols/ssprotocols.js';
import { assert } from 'node:console';
var SSGS = /** @class */ (function () {
    /**
     * @constructor
     * @param {number} port - the UDP port number to listen for SSGSCP packets, default is 1818
     * @param {function} onmessage - the callback function to handle incoming messages
     * @param {string} configFilePath - the path to the SSGS configuration file, default is './config.json'
     */
    function SSGS(port, onconnection, configFilePath) {
        if (port === void 0) { port = 1818; }
        if (configFilePath === void 0) { configFilePath = './config.json'; }
        this.port = port;
        this.onconnection = onconnection;
        this.configFilePath = configFilePath;
        this.socket = null;
        this.configFile = null;
        this.authorizedGateways = [];
        this.connectedClients = [];
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
            // loop over the sent messages and check if any need to be retransmitted, limit to 10 messages per client per tick
            var retransmittedCount = 0;
            for (var _b = 0, _c = client.sentMessages; _b < _c.length; _b++) {
                var sentMessage = _c[_b];
                if (retransmittedCount < 10 && now - sentMessage.timestamp > client.retransmissionTimeout) {
                    // retransmit the message
                    this.socket.send(sentMessage.packet, client.sourcePort, client.remoteAddress, function (err) {
                        if (err)
                            logIfSSGSDebug('Error: Could not send packet: ' + err);
                    });
                    logIfSSGSDebug('Retransmitting packet: ' + sentMessage.packetID + ', num pending: ' + client.sentMessages.length);
                    sentMessage.timestamp = Date.now();
                    retransmittedCount++;
                }
            }
        }
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
        var packet = {
            packetType: packetType,
            gatewayUID: client.gatewayUID,
            packetID: client.sendPacketID,
            payload: payload
        };
        var packedPacket = SSGSCP.packSSGSCP(packet, client.key);
        if (!packedPacket) {
            logIfSSGSDebug('Error: Could not pack packet: ' + SSGSCP.errMsg);
            return;
        }
        this.socket.send(packedPacket, client.sourcePort, client.remoteAddress, function (err) {
            if (err) {
                logIfSSGSDebug('Error: Could not send packet: ' + err);
            }
        });
        // add the sent message to the sentMessages list
        var sentMessage = {
            packetID: client.sendPacketID,
            timestamp: Date.now(),
            packet: packedPacket,
        };
        client.sentMessages.push(sentMessage);
        // increment the packet ID
        client.sendPacketID = (client.sendPacketID + 1) % 65536;
        // if the sentMessages list is too long, remove the oldest message
        if (client.sentMessages.length > SENT_MSG_LIST_MAX_LEN) {
            client.sentMessages.shift();
        }
    };
    /**
     * @method
     * @param {object} parsedPacket - the parsed packet object from SSGSCP.parseSSGSCP
     * @param {object} rinfo - the remote address information from the UDP socket
     * Processes the incoming packet and calls the onmessage callback function
     */
    SSGS.prototype.process = function (datagram, rinfo) {
        var _this = this;
        var _a, _b, _c, _d, _e, _f;
        var gatewayUID = SSGSCP.parsePacketGatewayUID(datagram);
        if (!gatewayUID) {
            logIfSSGSDebug('Error: Could not parse gateway UID from packet');
            return;
        }
        if (!this.isAuthorizedGateway(gatewayUID)) {
            logIfSSGSDebug('Error: Connecting gateway is not authorized in config');
            return;
        }
        var key = this.getGatewayKey(gatewayUID);
        if (!key) {
            logIfSSGSDebug('Error: Could not find key for gateway UID: ' + gatewayUID);
            return;
        }
        var parsedPacket = SSGSCP.parseSSGSCP(datagram, key);
        if (!parsedPacket) { // could not parse due to authentication error or other reason
            logIfSSGSDebug('Error: Could not parse packet: ' + SSGSCP.errMsg);
            this.sendCONNFAIL(rinfo, gatewayUID);
            return;
        }
        if (!parsedPacket.authSuccess) {
            logIfSSGSDebug('Error: Could not authenticate gateway');
            this.sendCONNFAIL(rinfo, gatewayUID);
            return;
        }
        // try find the Client state machine for this gateway client (in connectedClients)
        var client = this.connectedClients.find(function (c) { return SSGS.gatewayUIDsMatch(c.gatewayUID, parsedPacket.gatewayUID); });
        // if the client is not found, this is a new connection, so we need to add it to the connectedClients list
        if (!client) {
            if (parsedPacket.packetType === 1 /* PacketType.CONN */) {
                this.sendCONNACPT(rinfo, Buffer.from(key), parsedPacket.gatewayUID);
                var client_1 = {
                    gatewayUID: parsedPacket.gatewayUID,
                    sourcePort: rinfo.port,
                    remoteAddress: rinfo.address,
                    lastSeen: Date.now(),
                    sendPacketID: 0,
                    retransmissionTimeout: 2000,
                    sentMessages: [],
                    receivedMessageIDsFIFO: [],
                    key: Buffer.from(key),
                    onmessage: function (packet) { },
                    onreconnect: function () { },
                    send: function (payload) {
                        _this.sendMSG(client_1, 20 /* PacketType.MSGCONF */, payload);
                    }
                };
                this.connectedClients.push(client_1);
                this.onconnection(client_1);
                return;
            }
            else {
                logIfSSGSDebug('Error: Client not found in connectedClients and packet type is not CONN');
                this.sendCONNFAIL(rinfo, parsedPacket.gatewayUID);
                return;
            }
        }
        client.lastSeen = Date.now();
        switch (parsedPacket.packetType) {
            // CONNACPT is sent by the server to the client to indicate that the CONN packet was received
            case 1 /* PacketType.CONN */: {
                // we already have a client state machine but receivinng this could mean that the client restarted,
                // so we need to reset part of the state machine
                client.sendPacketID = 0;
                client.retransmissionTimeout = 2000; // assume RTT is 2000 ms for now
                client.sentMessages = [];
                client.receivedMessageIDsFIFO = [];
                client.remoteAddress = rinfo.address;
                client.sourcePort = rinfo.port;
                logIfSSGSDebug('Warning: Received CONN packet from already connected client, assuming client restarted');
                // send CONNACPT to client to indicate that we received the packet
                this.sendCONNACPT(rinfo, Buffer.from(key), parsedPacket.gatewayUID);
                setTimeout(function () {
                    client.onreconnect();
                }, client.retransmissionTimeout);
                return;
            }
            // RCPTOK is sent by the client or server to indicate that a packet was received correctly
            case 10 /* PacketType.RCPTOK */: {
                // packet we sent was received correctly by the client, so we can remove it from the sentMessages list
                var sentMessage = client.sentMessages.find(function (m) { return m.packetID === parsedPacket.packetID; });
                if (sentMessage) {
                    var index = client.sentMessages.indexOf(sentMessage);
                    client.sentMessages.splice(index, 1);
                }
                else {
                    logIfSSGSDebug('Warning: Received RCPTOK for packet ID ' + parsedPacket.packetID + ' but could not find it in sentMessages');
                }
                return;
            }
            // MSGSTATUS is sent by the client to the server and contains a Sensor Seal status update
            case 21 /* PacketType.MSGSTATUS */: {
                // check for duplicate packet ID in FIFO and ignore if found, otherwise add to FIFO
                if (client.receivedMessageIDsFIFO.includes(parsedPacket.packetID)) {
                    logIfSSGSDebug('Warning: Received duplicate MSGSTATUS packet ID ' + parsedPacket.packetID);
                    // send RCPTOK to client to indicate that we received the packet
                    this.sendRCPTOK(parsedPacket.packetID, rinfo, Buffer.from(key), parsedPacket.gatewayUID);
                    return;
                }
                else {
                    client.receivedMessageIDsFIFO.push(parsedPacket.packetID);
                    if (client.receivedMessageIDsFIFO.length > RECV_MSG_FIFO_MAX_LEN) {
                        client.receivedMessageIDsFIFO.shift(); // remove the oldest packet ID, shift left
                    }
                }
                // send RCPTOK to client to indicate that we received the packet
                this.sendRCPTOK(parsedPacket.packetID, rinfo, Buffer.from(key), parsedPacket.gatewayUID);
                // try parse the measurements from a variety of SSGSCP payload formats
                var sensorSealUpdateParams = SSProtocols.parse(parsedPacket.payload);
                // call the onmessage callback function
                var update = {
                    gatewayUID: parsedPacket.gatewayUID,
                    rawPayload: parsedPacket.payload,
                    sensorSealUID: (_a = sensorSealUpdateParams.sensorSealUID) !== null && _a !== void 0 ? _a : null,
                    temperature: (_b = sensorSealUpdateParams.temperature) !== null && _b !== void 0 ? _b : null,
                    vibration: (_c = sensorSealUpdateParams.vibration) !== null && _c !== void 0 ? _c : null,
                    rpm: (_d = sensorSealUpdateParams.rpm) !== null && _d !== void 0 ? _d : null,
                    voltage: (_e = sensorSealUpdateParams.voltage) !== null && _e !== void 0 ? _e : null,
                    msgID: (_f = sensorSealUpdateParams.msgID) !== null && _f !== void 0 ? _f : null,
                };
                client.onmessage(update);
                return;
            }
            // outbound server->gateway packet types (should never be received by server)
            case 20 /* PacketType.MSGCONF */: {
                logIfSSGSDebug('Error: Server received outbound server packet: ' + parsedPacket.packetType);
                return;
            }
            case 2 /* PacketType.CONNACPT */: {
                logIfSSGSDebug('Error: Server received outbound server packet: ' + parsedPacket.packetType);
                return;
            }
            case 3 /* PacketType.CONNFAIL */: {
                logIfSSGSDebug('Error: Server received outbound server packet: ' + parsedPacket.packetType);
                return;
            }
            default: {
                assert(false, 'Software Error: default clause in process() should never be reached');
            }
        }
    };
    /**
     * @method
     * @param {object} rinfo - the remote address information from the UDP socket
     * Sends a CONNFAIL packet to the remote address to indicate a connection failure
     */
    SSGS.prototype.sendCONNFAIL = function (rinfo, gatewayUID) {
        var fields = {
            packetType: 3 /* PacketType.CONNFAIL */,
            packetID: 0,
            gatewayUID: gatewayUID,
        };
        // CONNFAIL packets are not encrypted
        var packedPacket = SSGSCP.packSSGSCP(fields, Buffer.alloc(32));
        this.socket.send(packedPacket, rinfo.port, rinfo.address);
    };
    /**
     * @method
     * @param {object} rinfo - the remote address information from the UDP socket
     * Sends a CONNACPT packet to the remote address to indicate a connection success
     * This packet is sent in response to a CONN packet
     */
    SSGS.prototype.sendCONNACPT = function (rinfo, key, gatewayUID) {
        var fields = {
            packetType: 2 /* PacketType.CONNACPT */,
            packetID: 0,
            gatewayUID: gatewayUID,
        };
        var packedPacket = SSGSCP.packSSGSCP(fields, key);
        this.socket.send(packedPacket, rinfo.port, rinfo.address);
        logIfSSGSDebug('Sent CONNACPT to ' + rinfo.address + ':' + rinfo.port);
    };
    /**
     * @method
     * @param {number} packetID - the packet ID to send
     * @param {object} rinfo - the remote address information from the UDP socket
     * Sends a RCPTOK packet to the remote address to indicate that the packet with the given packet ID was received correctly
     */
    SSGS.prototype.sendRCPTOK = function (packetID, rinfo, key, gatewayUID) {
        var fields = {
            packetType: 10 /* PacketType.RCPTOK */,
            packetID: packetID,
            gatewayUID: gatewayUID,
        };
        var packedPacket = SSGSCP.packSSGSCP(fields, key);
        this.socket.send(packedPacket, rinfo.port, rinfo.address);
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
     * @param {string} configFilePath - the path to the SSGS configuration file
     * Loads and parses the configuration file and sets up the authorized gateways and key properties
     */
    SSGS.prototype.loadConfig = function (configFilePath) {
        return __awaiter(this, void 0, void 0, function () {
            var _a, _b, _c, _i, _d, gateway, uid, key;
            return __generator(this, function (_e) {
                switch (_e.label) {
                    case 0:
                        // load the config file
                        _a = this;
                        _c = (_b = JSON).parse;
                        return [4 /*yield*/, fs.readFile(configFilePath, 'utf8')];
                    case 1:
                        // load the config file
                        _a.configFile = _c.apply(_b, [_e.sent()]);
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
        if (gatewayUID1.length != 4 && gatewayUID2.length != 4) // should be 4 bytes long
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