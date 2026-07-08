'use strict';
require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const admin      = require('firebase-admin');
const nodemailer = require('nodemailer');
const path       = require('path');

// ─── Firebase Admin Init ──────────────────────────────────────────────────────
const serviceAccount = require('./serviceAccount.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  projectId:  'trackay-hospital-174c3',
});
const db = admin.firestore();

// ─── Express Setup ────────────────────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3001;

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '1mb' }));

// ─── Middleware: verify node API key ─────────────────────────────────────────
// ESP32-C6 nodes must send header:  x-node-key: <NODE_API_KEY>
function requireNodeKey(req, res, next) {
  const key = req.headers['x-node-key'];
  if (key !== process.env.NODE_API_KEY) {
    return res.status(401).json({ error: 'Invalid node key' });
  }
  next();
}

// ─── Audit helper ─────────────────────────────────────────────────────────────
async function audit(action, details, user = 'system') {
  await db.collection('auditlog').add({
    action, details, user,
    timestamp: admin.firestore.FieldValue.serverTimestamp(),
  });
}

// ─── Email helper ─────────────────────────────────────────────────────────────
async function sendAlertEmail(subject, body) {
  const cfg = process.env;
  if (!cfg.EMAIL_USER || !cfg.EMAIL_PASS || !cfg.EMAIL_TO) return;
  try {
    const transporter = nodemailer.createTransporter({
      host: cfg.EMAIL_SMTP || 'smtp.gmail.com',
      port: parseInt(cfg.EMAIL_PORT) || 587,
      secure: cfg.EMAIL_PORT == 465,
      auth: { user: cfg.EMAIL_USER, pass: cfg.EMAIL_PASS },
      tls: { rejectUnauthorized: false },
    });
    await transporter.sendMail({
      from: `"Trackay Alerts" <${cfg.EMAIL_FROM || cfg.EMAIL_USER}>`,
      to: cfg.EMAIL_TO, subject,
      html: `<div style="font-family:Arial,sans-serif;padding:16px;max-width:600px;">
        <h2 style="color:#1f6feb;">📡 Trackay Alert</h2>
        <p style="font-size:14px;line-height:1.6;">${body.replace(/\n/g,'<br/>')}</p>
        <hr/><p style="font-size:11px;color:#888;">Trackay 1.00.0 — Viking Medical and Surgical</p>
      </div>`,
    });
  } catch (e) { console.error('Email error:', e.message); }
}

// ═══════════════════════════════════════════════════════════════
// NODE DATA ENDPOINT
// ESP32-C6 posts BLE scan data here every 5 seconds
// POST /api/node/scan
// Header: x-node-key: <NODE_API_KEY>
// Body: { type, node, ward, nodeType, tags: [{mac, rssi, name, ibeacon}], gateway? }
// ═══════════════════════════════════════════════════════════════
app.post('/api/node/scan', requireNodeKey, async (req, res) => {
  try {
    const data = req.body;
    if (!data.node) return res.status(400).json({ error: 'node field required' });

    const now = admin.firestore.Timestamp.now();

    // Update node last seen
    const nodeRef = db.collection('nodes').doc(data.node);
    const nodeSnap = await nodeRef.get();
    if (!nodeSnap.exists) {
      // Auto-register node
      await nodeRef.set({
        name:       data.node,
        ward:       data.ward || '',
        type:       data.nodeType || 'ward',
        gateway:    data.gateway || null,
        fw:         data.fw || '',
        connection: 'wifi',
        ip:         req.ip,
        lastSeen:   now,
        createdAt:  now,
        autoRegistered: true,
      });
      await audit('NODE_AUTO_REGISTERED', `Node ${data.node} auto-registered via WiFi (${req.ip})`);
    } else {
      await nodeRef.update({ lastSeen: now, ip: req.ip, gateway: data.gateway || nodeSnap.data().gateway || null });
    }

    // Process each tag in the scan
    if (Array.isArray(data.tags)) {
      for (const tagData of data.tags) {
        if (!tagData.mac) continue;
        await processTagSighting(tagData.mac, data.node, data.ward || '', tagData.rssi, data.type || 'scan', tagData.name || '', tagData.ibeacon || null, data.gateway || null, now);
      }
    }

    // Handle exit events
    if (data.type === 'exit' && data.mac) {
      await handleExitDetection(data.mac, data.node, data.name || '', now);
    }

    res.json({ success: true, processed: data.tags?.length || 0 });
  } catch (e) {
    console.error('Scan error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// BOOT ENDPOINT — node announces itself
// POST /api/node/boot
// ═══════════════════════════════════════════════════════════════
app.post('/api/node/boot', requireNodeKey, async (req, res) => {
  try {
    const data = req.body;
    const now  = admin.firestore.Timestamp.now();
    const nodeRef = db.collection('nodes').doc(data.node);
    await nodeRef.set({
      name:       data.node,
      ward:       data.ward || '',
      type:       data.nodeType || 'ward',
      gateway:    data.gateway || null,
      fw:         data.fw || 'Trackay-1.00.0',
      connection: 'wifi',
      ip:         req.ip,
      lastSeen:   now,
      online:     true,
      lastBoot:   now,
    }, { merge: true });
    await audit('NODE_BOOT', `Node ${data.node} booted — WiFi IP: ${req.ip}, FW: ${data.fw}`);
    res.json({ success: true, serverTime: now.toDate().toISOString() });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Process tag sighting ─────────────────────────────────────────────────────
async function processTagSighting(mac, nodeName, ward, rssi, type, advName, ibeacon, gateway, now) {
  // Look up tag
  let tagSnap = null;
  const tagsByMac = await db.collection('tags').where('mac', '==', mac).limit(1).get();
  if (!tagsByMac.empty) { tagSnap = tagsByMac.docs[0]; }

  // Try by advName
  if (!tagSnap && advName) {
    const byName = await db.collection('tags').where('advName', '==', advName).limit(1).get();
    if (!byName.empty) {
      tagSnap = byName.docs[0];
      await tagSnap.ref.update({ mac, lastMacUpdate: now });
    }
  }

  // Try by iBeacon identity
  if (!tagSnap && ibeacon?.uuid) {
    const byIb = await db.collection('tags')
      .where('ibeacon.uuid', '==', ibeacon.uuid)
      .where('ibeacon.major', '==', ibeacon.major)
      .where('ibeacon.minor', '==', ibeacon.minor)
      .limit(1).get();
    if (!byIb.empty) {
      tagSnap = byIb.docs[0];
      await tagSnap.ref.update({ mac, lastMacUpdate: now });
    }
  }

  if (!tagSnap) {
    // Unknown tag — add to discovered
    const discQuery = await db.collection('discovered').where('mac', '==', mac).limit(1).get();
    if (discQuery.empty) {
      await db.collection('discovered').add({
        mac, advName: advName || '', ibeacon: ibeacon || null,
        firstSeenNode: nodeName, firstSeenWard: ward,
        firstSeen: now, lastSeen: now, lastRssi: rssi,
        status: 'unassigned',
      });
      await audit('TAG_DISCOVERED', `New BLE tag: ${advName || mac} at ${ward} via ${nodeName}`);
    } else {
      await discQuery.docs[0].ref.update({
        mac, lastSeen: now, lastRssi: rssi, lastNode: nodeName,
        advName: advName || discQuery.docs[0].data().advName || '',
        ibeacon: ibeacon || discQuery.docs[0].data().ibeacon || null,
      });
    }
    return;
  }

  // Known tag — update tag status
  const tag     = tagSnap.data();
  const tagId   = tagSnap.id;
  const wasOnline = tag.tagOnline !== false;
  const tagUpdate = {
    lastSeen:     now,
    tagOnline:    true,
    lastSeenNode: nodeName,
    lastSeenWard: ward,
    lastRssi:     rssi,
  };

  // Battery level
  if (ibeacon?.tx !== undefined) {
    if (ibeacon.tx > 0) {
      tagUpdate.batteryLevel = ibeacon.tx;
      if (ibeacon.tx < 20) {
        console.log(`Low battery: tag ${mac} at ${ibeacon.tx}%`);
      }
    } else {
      tagUpdate.txPower = ibeacon.tx;
    }
  }

  if (!wasOnline) {
    await audit('TAG_BACK_ONLINE', `Tag for asset came back online at ${ward}`);
  }

  await tagSnap.ref.update(tagUpdate);

  // Find linked asset
  const assetQuery = await db.collection('assets').where('tagId', '==', tagId).limit(1).get();
  if (assetQuery.empty) return;

  const assetRef  = assetQuery.docs[0].ref;
  const asset     = assetQuery.docs[0].data();
  const wasHome   = asset.currentLocation === asset.homeLocation;

  // Record movement
  await db.collection('movements').add({
    assetId: assetQuery.docs[0].id,
    tagMac: mac, node: nodeName, ward, gateway: gateway || null,
    rssi, timestamp: now, type,
  });

  // Update asset location
  await assetRef.update({
    currentLocation: ward,
    lastSeen: now,
    lastNode: nodeName,
    lastRssi: rssi,
    lastGateway: gateway || null,
  });

  // Flag if left home
  if (ward !== asset.homeLocation && wasHome) {
    await assetRef.update({ flagged: true });
    await audit('ASSET_LEFT_HOME', `${asset.equipmentName} left ${asset.homeLocation} → ${ward}`);
  }
}

// ─── Handle exit detection ────────────────────────────────────────────────────
async function handleExitDetection(mac, exitNode, advName, now) {
  let tagSnap = null;
  const q = await db.collection('tags').where('mac', '==', mac).limit(1).get();
  if (!q.empty) tagSnap = q.docs[0];
  if (!tagSnap && advName) {
    const q2 = await db.collection('tags').where('advName', '==', advName).limit(1).get();
    if (!q2.empty) tagSnap = q2.docs[0];
  }
  if (!tagSnap) return;

  const tag = tagSnap.data();
  const assetQ = await db.collection('assets').where('tagId', '==', tagSnap.id).limit(1).get();
  if (assetQ.empty) return;
  const asset = assetQ.docs[0].data();
  const assetId = assetQ.docs[0].id;

  // Check if already has an active authorized checkout
  const coQ = await db.collection('checkouts')
    .where('assetId', '==', assetId)
    .where('active', '==', true)
    .where('status', '==', 'authorized')
    .limit(1).get();
  if (!coQ.empty) return; // authorized — no alarm

  // Create alarm
  await db.collection('alarms').add({
    assetId, tagMac: mac, exitNode,
    assetName:    asset.equipmentName,
    serialNumber: asset.serialNumber,
    timestamp:    now,
    status:       'active',
    type:         'exit_attempt',
  });

  await audit('EXIT_ALARM', `${asset.equipmentName} (${asset.serialNumber}) at exit ${exitNode}`);

  // Email alert
  await sendAlertEmail(
    `🚨 EXIT ALARM — ${asset.equipmentName}`,
    `ALERT: Equipment detected at hospital exit.\n\nEquipment: ${asset.equipmentName}\nSerial Number: ${asset.serialNumber}\nExit Node: ${exitNode}\nHome Ward: ${asset.homeLocation}\nTime: ${new Date().toLocaleString()}\n\nCheck Trackay immediately.`
  );
}

// ─── Tag offline checker — runs every 60 seconds ──────────────────────────────
const TAG_OFFLINE_MS = (parseInt(process.env.TAG_OFFLINE_MINUTES) || 7) * 60 * 1000;

async function checkTagOnlineStatus() {
  try {
    const tags = await db.collection('tags').where('commissioned', '==', true).get();
    const now  = Date.now();
    for (const doc of tags.docs) {
      const tag = doc.data();
      if (!tag.lastSeen) continue;
      const lastSeenMs = tag.lastSeen.toDate ? tag.lastSeen.toDate().getTime() : new Date(tag.lastSeen).getTime();
      const msSince    = now - lastSeenMs;
      const isOnline   = msSince < TAG_OFFLINE_MS;

      if (!isOnline && tag.tagOnline !== false) {
        await doc.ref.update({ tagOnline: false });
        const minSince = Math.round(msSince / 60000);
        const assetQ   = await db.collection('assets').where('tagId', '==', doc.id).limit(1).get();
        const assetName = assetQ.empty ? tag.mac : assetQ.docs[0].data().equipmentName;
        await audit('TAG_OFFLINE', `Tag for "${assetName}" not seen for ${minSince} minutes`);
      } else if (isOnline && tag.tagOnline !== true) {
        await doc.ref.update({ tagOnline: true });
      }
    }
  } catch (e) { console.error('Tag checker error:', e.message); }
}

// ─── Service interval checker — runs every 12 hours ───────────────────────────
async function checkServiceIntervals() {
  try {
    const assets = await db.collection('assets').where('checkedOut', '==', false).get();
    const today  = new Date();
    for (const doc of assets.docs) {
      const a = doc.data();
      if (!a.nextService) continue;
      const next     = new Date(a.nextService);
      const diffDays = Math.ceil((next - today) / (1000 * 60 * 60 * 24));
      if (diffDays <= 30 && !a.serviceDueFlagged) {
        const reason = diffDays >= 0
          ? `Service due in ${diffDays} day(s)`
          : `Service overdue by ${Math.abs(diffDays)} day(s)`;
        await doc.ref.update({ serviceDueFlagged: true, serviceDueReason: reason });
        await audit('SERVICE_DUE_FLAGGED', `${a.equipmentName} (${a.serialNumber}) — ${reason}`);
        await sendAlertEmail(
          `🔧 Service Due — ${a.equipmentName}`,
          `${a.equipmentName} (S/N: ${a.serialNumber}) — ${reason}\nHome Ward: ${a.homeLocation}`
        );
      }
    }
  } catch (e) { console.error('Service checker error:', e.message); }
}

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', service: 'Trackay Backend', time: new Date().toISOString() }));

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Trackay backend running on port ${PORT}`);
  console.log(`   Project: trackay-hospital-174c3`);
  console.log(`   Tag offline timeout: ${TAG_OFFLINE_MS / 60000} minutes`);

  // Start background checkers
  setInterval(checkTagOnlineStatus, 60 * 1000);
  setInterval(checkServiceIntervals, 12 * 60 * 60 * 1000);
  checkServiceIntervals(); // run once on startup
});

module.exports = app;
