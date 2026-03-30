

import SSGS from './index.js';

// Create a new Sensor Seal Gateway Server that listens on UDP port 1818
const server = new SSGS(1818, client => {
    // Called when a new client connects
    console.log('New client connected');

    // Print all updates received from the client (gateeway)
    client.onupdate = update => {
        console.log(`\nReceived Sensor Seal update via gateway ${SSGS.uidToString(update.viaGatewayUID)}:`);
        console.log(`Sensor Seal UID: ${SSGS.uidToString(update.sensorSealUID)}`);
        console.log(`Temperature: ${update.temperature} deg C`);
        console.log(`Vibration: ${update.vibration} mm/s^2`);
        console.log(`Speed: ${update.rpm} rpm`);
        console.log(`Voltage: ${update.voltage} mV`);
        console.log(`Update ID: ${update.updateID}`);
    };

    // The code below demonstrates some of the more advanced features of SSGS
    // and in most cases they are not needed. You can delete this code 
    // if you don't need it.

    // Called when the gateway reconnects to an existing session (power to gateway was lost or it restarted)
    client.onreconnect = () => {
        console.log('Gateway reconnected');
    }

    // Called when the gateway has not been seen for ~30 seconds. The session is removed and the client object is now stale.
    client.ondisconnect = () => {
        console.log('Gateway disconnected');
    }

    // Send a message to the client
    // 0x02 is the SSGSCP message subtype for remote terminal input
    // Should receive a remote terminal output message 'hello world' from the gateway 
    client.send(Buffer.from('\x02echo hello world\n'));
    
});

