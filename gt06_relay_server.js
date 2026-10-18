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
// Where the relay asks Base44 for queued device commands (reporting mode, etc.).
// Defaults to the same function URL used for pings, with the name swapped.
const BASE44_COMMANDS_URL = process.env.BASE44_COMMANDS_URL || BASE44_WEBHOOK_URL.replace(/ingestGpsPing$/, 'deviceCommands');
const COMMAND_POLL_MS = Number(process.env.COMMAND_POLL_MS || 60000);
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

// 0xA0 / 0xA3 are the 4G variant of GT06: 0xA0 = GPS position (same field layout as
// 0x22 but with longer cell-tower info after it), 0xA3 = the periodic status/heartbeat
// packet. If the server does not answer 0xA3, the tracker drops the connection after
// three tries and logs in again (seen every ~7 minutes on IMEI 357956373407958).
const PROTOCOL = { LOGIN: 0x01, GPS_LOCATION: 0x12, GPS_LBS_STATUS: 0x22, HEARTBEAT: 0x13, ALARM: 0x16, LBS_ONLY: 0x18, COMMAND: 0x80, COMMAND_REPLY: 0x15, GPS_4G: 0xa0, HEARTBEAT_4G: 0xa3 };

function decodePacket(packet) {
  const length = packet[2];
  const protocolNumber = packet[3];
  const data = packet.slice(4, 4 + length - 5);
  const serialNumber = packet.slice(packet.length - 6, packet.length - 4);

  switch (protocolNumber) {
    case PROTOCOL.LOGIN:
      // The login packet carries the IMEI as 16 BCD digits, so a 15-digit IMEI
      // arrives with a leading 0 (e.g. 0351840620502686). Strip it so it matches
      // the real IMEI printed on the device.
      return { type: 'login', imei: data.slice(0, 8).toString('hex').replace(/^0/, ''), serialNumber };
    case PROTOCOL.GPS_LOCATION:
    case PROTOCOL.GPS_LBS_STATUS:
      return { ...decodeGpsPacket(data), serialNumber };
    case PROTOCOL.GPS_4G:
      // Same first 18 bytes as 0x22 (time, satellites, lat, lon, speed, course/status).
      // This tracker leaves the "GPS fixed" status bit at 0 even when it reports 12 satellites and
      // coordinates that match a second tracker sitting next to it (seen 2026-10-18), so for 4G
      // packets also trust the satellite count in the low nibble of byte 6.
      {
        const g = decodeGpsPacket(data);
        const sats = data[6] & 0x0f;
        const plausible = Math.abs(g.latitude) > 0.01 && Math.abs(g.longitude) > 0.01;
        return { ...g, satellites: sats, gpsFixed: g.gpsFixed || (sats >= 4 && plausible), serialNumber, via4g: true };
      }
    case PROTOCOL.HEARTBEAT_4G:
      // Payload meaning is not documented for this tracker yet; we only need to answer it.
      return { type: 'heartbeat4g', serialNumber, raw: data.toString('hex') };
    case PROTOCOL.HEARTBEAT: {
      // data = [terminal info 1][battery 1][GSM signal 1][ext voltage/mode 1][language 1]
      // Wireless trackers (W18L-E etc.) report battery as a percentage in byte 2.
      return {
        type: 'heartbeat',
        serialNumber,
        battery: data.length > 1 ? Math.min(data[1], 100) : null,
        signal: data.length > 2 ? data[2] : null,
        charging: data.length > 0 ? (data[0] & 0x04) !== 0 : null,
      };
    }
    case PROTOCOL.LBS_ONLY:
      // Cell-tower-only report (no GPS fix, usually indoors). Not forwarded.
      return { type: 'lbs', serialNumber };
    case PROTOCOL.COMMAND_REPLY: {
      // data = [cmdLen 1][server flag 4][content N][language 2]
      const cmdLen = data[0];
      const flag = data.readUInt32BE(1);
      const text = data.slice(5, 1 + cmdLen).toString('ascii');
      return { type: 'command_reply', flag, text, serialNumber };
    }
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

// ---------- Server -> tracker commands (protocol 0x80) ----------
// Same text commands as SMS (e.g. "STATIC,240#"), sent over the tracker's live
// connection - this is how WhatsGPS delivers its commands.
let commandSerial = 1;
function buildCommand(flag, text) {
  const content = Buffer.from(text, 'ascii');
  const flagBuf = Buffer.alloc(4);
  flagBuf.writeUInt32BE(flag >>> 0);
  const serial = Buffer.alloc(2);
  serial.writeUInt16BE(commandSerial++ & 0xffff);
  // length byte = protocol(1) + cmdLen(1) + flag(4) + content(N) + serial(2) + crc(2)
  const body = Buffer.concat([Buffer.from([PROTOCOL.COMMAND, 4 + content.length]), flagBuf, content, serial]);
  const withLength = Buffer.concat([Buffer.from([body.length + 2]), body]);
  const crc = crc16X25(withLength);
  return Buffer.concat([
    Buffer.from([0x78, 0x78]), withLength,
    Buffer.from([(crc >> 8) & 0xff, crc & 0xff]), Buffer.from([0x0d, 0x0a]),
  ]);
}

const imeiSockets = new Map();   // imei -> live socket
const inFlight = new Map();      // flag -> { id, imei, remaining, replies: [] }
let nextFlag = 1;

async function callCommandsApi(body) {
  const res = await fetch(BASE44_COMMANDS_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${RELAY_SECRET}` },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
}

async function reportCommand(update) {
  try { await callCommandsApi({ action: 'report', ...update }); }
  catch (err) { console.error('[relay] could not report command status:', err.message); }
}

// Ask Base44 for queued commands and push the ones whose tracker is connected.
async function pushPendingCommands(onlyImei) {
  const imeis = onlyImei ? [onlyImei] : [...imeiSockets.keys()];
  if (imeis.length === 0) return;
  let list;
  try {
    const out = await callCommandsApi({ action: 'list', imeis });
    list = out.commands || [];
  } catch (err) {
    console.error('[relay] could not fetch commands:', err.message);
    return;
  }
  for (const cmd of list) {
    const socket = imeiSockets.get(cmd.imei);
    if (!socket || socket.destroyed) continue;
    const lines = String(cmd.text).split('\n').map((l) => l.trim()).filter(Boolean);
    const flag = nextFlag++;
    inFlight.set(flag, { id: cmd.id, imei: cmd.imei, remaining: lines.length, replies: [] });
    for (const line of lines) {
      socket.write(buildCommand(flag, line));
      console.log(`[relay] sent command to imei=${cmd.imei}: ${line}`);
    }
    await reportCommand({ id: cmd.id, imei: cmd.imei, status: 'sent' });
  }
}

function handleCommandReply(imei, decoded) {
  console.log(`[relay] tracker reply imei=${imei || 'unknown'}: ${decoded.text}`);
  const entry = inFlight.get(decoded.flag);
  if (!entry) {
    // Relay restarted since sending, or reply to an SMS-style command: let Base44 match by IMEI.
    reportCommand({ imei, status: 'confirmed', reply: decoded.text });
    return;
  }
  entry.replies.push(decoded.text);
  entry.remaining -= 1;
  if (entry.remaining <= 0) {
    inFlight.delete(decoded.flag);
    reportCommand({ id: entry.id, imei: entry.imei, status: 'confirmed', reply: entry.replies.join(' | ') });
  }
}

// ---------- Battery / signal status (from heartbeat packets) ----------
// Heartbeats arrive every few minutes; tell Base44 at most every 15 minutes
// per tracker, or sooner if the battery percentage changed by 5 or more.
const lastStatusSent = new Map(); // imei -> { at, battery }
const STATUS_MIN_MS = Number(process.env.STATUS_MIN_MS || 15 * 60 * 1000);
async function maybeReportStatus(imei, hb) {
  if (!imei || hb.battery == null) return;
  const prev = lastStatusSent.get(imei);
  const now = Date.now();
  if (prev && now - prev.at < STATUS_MIN_MS && Math.abs(hb.battery - prev.battery) < 5) return;
  lastStatusSent.set(imei, { at: now, battery: hb.battery });
  console.log(`[relay] status imei=${imei} battery=${hb.battery}% signal=${hb.signal} charging=${hb.charging}`);
  try {
    await callCommandsApi({ action: 'status', imei, battery: hb.battery, signal: hb.signal, charging: hb.charging });
  } catch (err) {
    console.error('[relay] could not report status:', err.message);
  }
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
            imeiSockets.set(decoded.imei, socket);
            console.log(`[relay] login imei=${decoded.imei} from ${remoteId}`);
            socket.write(buildAck(PROTOCOL.LOGIN, decoded.serialNumber));
            // Deliver anything queued for this tracker as soon as it connects.
            setTimeout(() => pushPendingCommands(decoded.imei), 2000);
            continue;
          }

          const imei = socketImeiMap.get(socket);

          if (decoded.type === 'gps' || decoded.type === 'alarm') {
            // 4G position packets: do not send the old 0x12 ack back. Only log, forward, move on.
            if (!decoded.via4g) {
              const ackProtocol = decoded.type === 'alarm' ? PROTOCOL.ALARM : PROTOCOL.GPS_LOCATION;
              socket.write(buildAck(ackProtocol, decoded.serialNumber));
            }
            if (decoded.via4g) {
              console.log(`[relay] 4G position imei=${imei || 'unknown'} fixed=${decoded.gpsFixed} sats=${decoded.satellites} lat=${decoded.latitude.toFixed(5)} lon=${decoded.longitude.toFixed(5)} speed=${decoded.speed}`);
            }
            if (imei && decoded.gpsFixed) {
              forwardToBase44(imei, decoded);
            }
            continue;
          }

          if (decoded.type === 'heartbeat4g') {
            // Answer with the same protocol number and serial, same frame as the other acks.
            socket.write(buildAck(PROTOCOL.HEARTBEAT_4G, decoded.serialNumber));
            console.log(`[relay] 4G heartbeat imei=${imei || 'unknown'} payload=${decoded.raw}`);
            continue;
          }

          if (decoded.type === 'heartbeat') {
            socket.write(buildAck(PROTOCOL.HEARTBEAT, decoded.serialNumber));
            maybeReportStatus(imei, decoded);
            continue;
          }

          if (decoded.type === 'command_reply') {
            handleCommandReply(imei, decoded);
            continue;
          }

          if (decoded.type === 'lbs') {
            console.log(`[relay] tower-only report (no GPS fix) imei=${imei || 'unknown'} - waiting for a GPS fix`);
            continue;
          }

          console.log(`[relay] unhandled packet type from ${remoteId}:`, packet.toString('hex'));
        } catch (err) {
          console.error(`[relay] error decoding packet from ${remoteId}:`, err.message);
        }
      }
    });

    socket.on('close', () => {
      const closedImei = socketImeiMap.get(socket);
      if (closedImei && imeiSockets.get(closedImei) === socket) imeiSockets.delete(closedImei);
      socketImeiMap.delete(socket);
      console.log(`[relay] connection closed: ${remoteId}`);
    });

    socket.on('error', (err) => console.error(`[relay] socket error ${remoteId}:`, err.message));
  });

  // Only polls while at least one tracker is connected.
  setInterval(() => pushPendingCommands(), COMMAND_POLL_MS);

  server.listen(PORT, () => console.log(`[relay] listening on port ${PORT}, forwarding to ${BASE44_WEBHOOK_URL}`));
  return server;
}

startRelay();
