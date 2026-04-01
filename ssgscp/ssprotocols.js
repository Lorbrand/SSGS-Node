/*
 * Lorbrand Sensor Seal Gateway Server
 * Copyright (c) 2023-2026 Lorbrand (Pty) Ltd
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this repository.
 */
function buffersEqual(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    for (var i = 0; i < a.length; i++) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}
function parseSSRB(parsedSSGSCP) {
    // check if the packet is an SSRB packet
    var messageData = parsedSSGSCP.payload.subarray(1);
    if (!buffersEqual(messageData.subarray(0, 4), [0x53, 0x53, 0x52, 0x42])) {
        return null;
    }
    var offset = 4;
    var roundTo1dp = function (num) { return Math.round(num * 10) / 10; };
    var ssrbVersion = messageData[offset];
    offset += 1;
    if (ssrbVersion < 2) {
        return null;
    }
    var sensorSealUID = messageData.subarray(offset, offset + 4);
    offset += 4;
    var msgID = messageData.readUInt32LE(offset);
    offset += 4;
    var temperature = roundTo1dp(messageData.readFloatLE(offset));
    offset += 4;
    var rpm = roundTo1dp(messageData.readFloatLE(offset));
    offset += 4;
    var vibration = messageData.readUInt32LE(offset);
    offset += 4;
    var voltage = messageData.readUInt32LE(offset);
    return {
        sensorSealUID: sensorSealUID,
        viaGatewayUID: parsedSSGSCP.gatewayUID,
        updateID: msgID,
        temperature: temperature === 0 ? null : temperature,
        vibration: vibration === 0 ? null : vibration,
        voltage: voltage === 0 ? null : voltage,
        rpm: rpm === 0 ? null : rpm
    };
}
var SSProtocols = {
    parse: function (parsedSSGSCP) {
        var messageSubtype = parsedSSGSCP.payload[0];
        var messageData = parsedSSGSCP.payload.subarray(1);
        switch (messageSubtype) {
            case 3 /* MessageSubtype.REMOTE_TERMINAL_OUTPUT */:
                return {
                    gatewayUID: parsedSSGSCP.gatewayUID,
                    rawPayload: parsedSSGSCP.payload,
                    data: messageData.toString(),
                    messageType: 3 /* MessageSubtype.REMOTE_TERMINAL_OUTPUT */
                };
            case 83 /* MessageSubtype.SSRB_UPDATE */:
                var ssrbUpdate = parseSSRB(parsedSSGSCP);
                return {
                    gatewayUID: parsedSSGSCP.gatewayUID,
                    rawPayload: parsedSSGSCP.payload,
                    data: ssrbUpdate,
                    messageType: ssrbUpdate ? 83 /* MessageSubtype.SSRB_UPDATE */ : 0 /* MessageSubtype.INVALID */
                };
            case 1 /* MessageSubtype.PING_PONG */:
                if (parsedSSGSCP.payload.length < 2) {
                    return null;
                }
                return {
                    gatewayUID: parsedSSGSCP.gatewayUID,
                    rawPayload: parsedSSGSCP.payload,
                    data: parsedSSGSCP.payload[1],
                    messageType: 1 /* MessageSubtype.PING_PONG */
                };
            case 4 /* MessageSubtype.WAKEUP_SCAN */:
                return {
                    gatewayUID: parsedSSGSCP.gatewayUID,
                    rawPayload: parsedSSGSCP.payload,
                    data: null,
                    messageType: 4 /* MessageSubtype.WAKEUP_SCAN */
                };
        }
        return null;
    }
};
export default SSProtocols;
