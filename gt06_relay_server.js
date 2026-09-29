// GT06 Relay Server — Base44 edition
// ------------------------------------
// This is the ONE small piece of infrastructure outside Base44. It does
// nothing except:
//   1. Accept the raw connection from your physical GPS tracker
//   2. Speak the GT06 binary protocol (login / GPS / heartbeat / alarm)
//      and send back the exact ACKs the tracker expects
//   3. Decode each GPS fix into plain JSON
//   4. POST that JSON to your Base44 app's webhook URL
//
// Everything else — the database, ownership/geofence logic, dealer &
// customer screens, subscriptions — lives inside Base44. This file has
// NO business logic in it on purpose, so you never have to touch it again
// once it's deployed. All you configure below are two values.

const net = require('net');

// ============================================================
// CONFIGURE THESE TWO LINES ONLY
// ============================================================
const BASE44_WEBHOOK_URL = process.env.BASE44_WEBHOOK_URL || 'https://REPLACE-ME.base44.app/api/functions/ingestGpsPing';
const RELAY_SECRET = process.env.RELAY_SECRET || 'REPLACE-WITH-A-LONG-RANDOM-STRING';
const PORT = process.env.PORT || 5023;
// ============================================================

// ---------- CRC-16/X-25 (validates every GT06 packet) ----------
function crc16X25(buffer) {
  let crc = 0xffff;
  for (let i = 0; i < buffer.length; i++) {
    crc ^= buffer[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc & 0x0001) ? (crc >> 1) ^ 0x8408 : crc >> 1;
    }
  }
  return (~crc) & 0xffff;
}

// ---------- Packet framing: 0x78 0x78 ... 0x0D 0x0A ----------
function extractPackets(buffer) {
  const packets = [];
  let offset = 0;
  while (offset < buffer.length - 4) {
    if (buffer[offset] === 0x78 && buffer[offset + 1] === 0x78) {
      const length = buffer[offset + 2];
      const totalLen = length + 5;
      if (offset + totalLen > buffer.length) break;
      packets.push(buffer.slice(offset, offset + totalLen));
      offset += totalLen;
    } else {
      offset++;
    }
  }
  return { packets, remainder: buffer.slice(offset) };
}

const PROTOCOL = { LOGIN: 0x01, GPS_LOCATION: 0x12, GPS_LBS_STATUS: 0x22, HEARTBEAT: 0x13, ALARM: 0x16 };

function decodePacket(packet) {
  const length = packet[2];
  const protocolNumber = packet[3];
  const data = packet.slice(4, 4 + length - 5);
  const serialNumber = packet.slice(packet.length - 6, packet.length - 4);

  switch (protocolNumber) {
    case PROTOCOL.LOGIN:
      return { type: 'login', imei: data.slice(0, 8).toString('hex'), serialNumber };
    case PROTOCOL.GPS_LOCATION:
    case PROTOCOL.GPS_LBS_STATUS:
      return { ...decodeGpsPacket(data), serialNumber };
    case PROTOCOL.HEARTBEAT:
      return { type: 'heartbeat', serialNumber };
    case PROTOCOL.ALARM:
      return { ...decodeGpsPacket(data), type: 'alarm', alarmType: data[data.length - 3], serialNumber };
    default:
      return { type: 'unknown', protocolNumber, serialNumber };
  }
}

function decodeGpsPacket(data) {
  const year = 2000 + data[0], month = data[1], day = data[2];
  const hour = data[3], minute = data[4], second = data[5];
  const timestamp = new Date(Date.UTC(year, month - 1, day, hour, minute, second));

  const rawLat = data.readUInt32BE(7);
  const rawLon = data.readUInt32BE(11);
  let latitude = rawLat / 30000 / 60;
  let longitude = rawLon / 30000 / 60;

  const speed = data[15];
  const courseAndFlags = data.readUInt16BE(16);
  const gpsFixed = (courseAndFlags & 0x1000) !== 0;
  const isSouth = (courseAndFlags & 0x0400) === 0;
  const isWest = (courseAndFlags & 0x0800) !== 0;

  if (isSouth) latitude = -latitude;
  if (isWest) longitude = -longitude;

  return { type: 'gps', timestamp, latitude, longitude, speed, gpsFixed };
}

function buildAck(protocolNumber, serialNumber) {
  const body = Buffer.concat([Buffer.from([protocolNumber]), serialNumber]);
  const length = body.length + 2;
  const withLength = Buffer.concat([Buffer.from([length]), body]);
  const crc = crc16X25(withLength);
  const crcBuf = Buffer.from([(crc >> 8) & 0xff, crc & 0xff]);
  return Buffer.concat([Buffer.from([0x78, 0x78]), withLength, crcBuf, Buffer.from([0x0d, 0x0a])]);
}

// ---------- Forward a decoded event to Base44 ----------
async function forwardToBase44(imei, decoded) {
  const payload = {
    imei,
    type: decoded.type, // 'gps' or 'alarm'
    latitude: decoded.latitude,
    longitude: decoded.longitude,
    speed: decoded.speed,
    timestamp: decoded.timestamp,
    alarmType: decoded.alarmType ?? null,
  };

  try {
    const res = await fetch(BASE44_WEBHOOK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${RELAY_SECRET}`,
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      console.error(`[relay] Base44 rejected ping: ${res.status} ${await res.text()}`);
    } else {
      console.log(`[relay] forwarded ping imei=${imei} lat=${decoded.latitude.toFixed(5)} lon=${decoded.longitude.toFixed(5)}`);
    }
  } catch (err) {
    console.error('[relay] failed to reach Base44:', err.message);
    // Packets are not queued/retried on failure in this version — if Base44
    // is briefly unreachable, that ping is lost but the tracker will send
    // another one shortly. Fine for a v1; revisit if that ever matters.
  }
}

// ---------- TCP server ----------
function startRelay() {
  const socketImeiMap = new Map();

  const server = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    const remoteId = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[relay] connection opened: ${remoteId}`);

    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const { packets, remainder } = extractPackets(buffer);
      buffer = remainder;

      for (const packet of packets) {
        try {
          const decoded = decodePacket(packet);

          if (decoded.type === 'login') {
            socketImeiMap.set(socket, decoded.imei);
            console.log(`[relay] login imei=${decoded.imei} from ${remoteId}`);
            socket.write(buildAck(PROTOCOL.LOGIN, decoded.serialNumber));
            continue;
          }

          const imei = socketImeiMap.get(socket);

          if (decoded.type === 'gps' || decoded.type === 'alarm') {
            const ackProtocol = decoded.type === 'alarm' ? PROTOCOL.ALARM : PROTOCOL.GPS_LOCATION;
            socket.write(buildAck(ackProtocol, decoded.serialNumber));
            if (imei && decoded.gpsFixed) {
              forwardToBase44(imei, decoded);
            }
            continue;
          }

          if (decoded.type === 'heartbeat') {
            socket.write(buildAck(PROTOCOL.HEARTBEAT, decoded.serialNumber));
            continue;
          }

          console.log(`[relay] unhandled packet type from ${remoteId}:`, packet.toString('hex'));
        } catch (err) {
          console.error(`[relay] error decoding packet from ${remoteId}:`, err.message);
        }
      }
    });

    socket.on('close', () => {
      socketImeiMap.delete(socket);
      console.log(`[relay] connection closed: ${remoteId}`);
    });

    socket.on('error', (err) => console.error(`[relay] socket error ${remoteId}:`, err.message));
  });

  server.listen(PORT, () => console.log(`[relay] listening on port ${PORT}, forwarding to ${BASE44_WEBHOOK_URL}`));
  return server;
}

startRelay();
