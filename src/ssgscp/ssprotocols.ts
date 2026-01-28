import { ParsedSSGSCPPacket } from "./ssgscp";
import { MessageSubtype } from "./ssgscp";
import { Buffer } from "node:buffer";

export type SensorSealUpdate = {
    sensorSealUID: Buffer; // the UID of the sensor seal that sent the update
    viaGatewayUID: Buffer; // the UID of the gateway that sent the update
    updateID: number; // the update ID of the update
    temperature: number | null; // the temperature value in degrees Celsius, or null if not present
    vibration: number | null; // the vibration value mm/s^2 , or null if not present
    voltage: number | null; // the generated voltage in volts, or null if not present
    rpm: number | null; // the RPM value, or null if not present
};

export type ParsedMessage = {
    gatewayUID: Buffer; // the UID of the gateway that sent the update
    rawPayload: Buffer; // the raw payload contents of the SSGSCP packet
    data: SensorSealUpdate | string | number | null; // the parsed data
    messageType: MessageSubtype; // the type of message
};

function buffersEqual(a, b) {
    if (a.length !== b.length) {
        return false;
    }

    for (let i = 0; i < a.length; i++) {
        if (a[i] != b[i]) {
            return false;
        }
    }

    return true;
}

function parseSSRB(parsedSSGSCP: ParsedSSGSCPPacket): SensorSealUpdate {
    // check if the packet is an SSRB packet
    const messageData = parsedSSGSCP.payload.subarray(1);

    if (!buffersEqual(messageData.subarray(0, 4), [0x53, 0x53, 0x52, 0x42])) {
        return null;
    }

    let offset = 4;

    const roundTo1dp = (num: number) => Math.round(num * 10) / 10;

    const ssrbVersion = messageData[offset];
    offset += 1;

    if (ssrbVersion < 2) {
        return null;
    }

    const sensorSealUID = messageData.subarray(offset, offset + 4);
    offset += 4;

    const msgID = messageData.readUInt32LE(offset);
    offset += 4;

    const temperature = roundTo1dp(messageData.readFloatLE(offset));
    offset += 4;

    const rpm = roundTo1dp(messageData.readFloatLE(offset));
    offset += 4;

    const vibration = messageData.readUInt32LE(offset);
    offset += 4;

    const voltage = messageData.readUInt32LE(offset);

    return <SensorSealUpdate>{
        sensorSealUID,
        viaGatewayUID: parsedSSGSCP.gatewayUID,
        updateID: msgID,
        temperature: temperature === 0 ? null : temperature,
        vibration: vibration === 0 ? null : vibration,
        voltage: voltage === 0 ? null : voltage,
        rpm: rpm === 0 ? null : rpm
    };
}

const SSProtocols = {


    parse: function (parsedSSGSCP: ParsedSSGSCPPacket): ParsedMessage {

        const messageSubtype = parsedSSGSCP.payload[0];
        const messageData = parsedSSGSCP.payload.subarray(1);

        switch (messageSubtype) {
            case MessageSubtype.REMOTE_TERMINAL_OUTPUT:
                return {
                    gatewayUID: parsedSSGSCP.gatewayUID,
                    rawPayload: parsedSSGSCP.payload,
                    data: messageData.toString(),
                    messageType: MessageSubtype.REMOTE_TERMINAL_OUTPUT
                };

            case MessageSubtype.SSRB_UPDATE:
                const ssrbUpdate = parseSSRB(parsedSSGSCP);
                return {
                    gatewayUID: parsedSSGSCP.gatewayUID,
                    rawPayload: parsedSSGSCP.payload,
                    data: ssrbUpdate,
                    messageType: ssrbUpdate ? MessageSubtype.SSRB_UPDATE : MessageSubtype.INVALID
                };
            case MessageSubtype.PING_PONG:
                if (parsedSSGSCP.payload.length < 2) {
                    return null;
                }
                return {
                    gatewayUID: parsedSSGSCP.gatewayUID,
                    rawPayload: parsedSSGSCP.payload,
                    data: parsedSSGSCP.payload[1],
                    messageType: MessageSubtype.PING_PONG
                };

            case MessageSubtype.WAKEUP_SCAN:
                return {
                    gatewayUID: parsedSSGSCP.gatewayUID,
                    rawPayload: parsedSSGSCP.payload,
                    data: null,
                    messageType: MessageSubtype.WAKEUP_SCAN
                };
                

        }

        return null;
    }
};

export default SSProtocols; 
