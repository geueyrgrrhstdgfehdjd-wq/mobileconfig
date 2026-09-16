const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

// ==============================
// NEXTRA ADMIN KEY
// ==============================

const ADMIN_KEY = "CEO8787GH";

// ==============================
// DATABASE
// ==============================

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "keys.json");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, "[]", "utf8");
}

// ==============================
// EXPRESS
// ==============================

app.use(express.json());

app.use(
  express.static(
    path.join(__dirname, "..", "frontend")
  )
);

// ==============================
// DATABASE FUNCTIONS
// ==============================

function readKeys() {
  try {
    return JSON.parse(
      fs.readFileSync(DB_FILE, "utf8")
    );
  } catch (error) {
    console.error(error);
    return [];
  }
}

function saveKeys(keys) {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify(keys, null, 2),
    "utf8"
  );
}

// ==============================
// GENERATE KEY
// ==============================

function generateKey() {
  const part1 = crypto
    .randomBytes(5)
    .toString("hex")
    .toUpperCase();

  const part2 = crypto
    .randomBytes(3)
    .toString("hex")
    .toUpperCase();

  return `NX-${part1}-${part2}`;
}

// ==============================
// SESSION
// ==============================

const userSessions = new Map();
const adminSessions = new Set();

// ==============================
// USER AUTH
// ==============================

function userAuth(req, res, next) {
  const auth =
    req.headers.authorization || "";

  const token = auth.replace(
    "Bearer ",
    ""
  );

  if (!token) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  const session =
    userSessions.get(token);

  if (!session) {
    return res.status(401).json({
      error: "Invalid session"
    });
  }

  const keys = readKeys();

  const key = keys.find(
    item => item.id === session.keyId
  );

  if (!key) {
    return res.status(401).json({
      error: "Key not found"
    });
  }

  if (key.revoked) {
    return res.status(403).json({
      error: "Key revoked"
    });
  }

  if (
    key.expires_at &&
    new Date(key.expires_at).getTime() <=
      Date.now()
  ) {
    return res.status(403).json({
      error: "Key expired"
    });
  }

  req.nextraKey = key;

  next();
}

// ==============================
// ADMIN AUTH
// ==============================

function adminAuth(req, res, next) {
  const auth =
    req.headers.authorization || "";

  const token = auth.replace(
    "Bearer ",
    ""
  );

  if (
    !token ||
    !adminSessions.has(token)
  ) {
    return res.status(401).json({
      error: "Admin unauthorized"
    });
  }

  next();
}

// ==============================
// HEALTH
// ==============================

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      ok: true,
      service: "NEXTRA",
      time: new Date().toISOString()
    });
  }
);

// ==============================
// VERIFY KEY
// ==============================

app.post(
  "/api/verify",
  (req, res) => {
    try {
      const keyValue =
        String(req.body.key || "").trim();

      if (!keyValue) {
        return res.status(400).json({
          error: "Key is required"
        });
      }

      const keys = readKeys();

      const key = keys.find(
        item =>
          item.key === keyValue &&
          item.revoked !== true
      );

      if (!key) {
        return res.status(401).json({
          error: "Invalid key"
        });
      }

      // ==========================
      // FIRST ACTIVATION
      // ==========================

      if (!key.activated_at) {
        key.activated_at =
          new Date().toISOString();

        if (
          key.duration_days &&
          key.duration_days > 0
        ) {
          key.expires_at =
            new Date(
              Date.now() +
                key.duration_days *
                  24 *
                  60 *
                  60 *
                  1000
            ).toISOString();
        }

        saveKeys(keys);
      }

      // ==========================
      // EXPIRATION
      // ==========================

      if (
        key.expires_at &&
        new Date(key.expires_at).getTime() <=
          Date.now()
      ) {
        return res.status(403).json({
          error: "Key expired"
        });
      }

      // ==========================
      // CREATE USER SESSION
      // ==========================

      const token =
        crypto.randomBytes(32).toString("hex");

      userSessions.set(token, {
        keyId: key.id
      });

      res.json({
        success: true,
        token,
        expires_at:
          key.expires_at || null,
        lifetime:
          !key.duration_days ||
          key.duration_days === 0
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Server error"
      });
    }
  }
);

// ==============================
// USER INFO
// ==============================

app.get(
  "/api/me",
  userAuth,
  (req, res) => {
    const key = req.nextraKey;

    res.json({
      success: true,
      expires_at:
        key.expires_at || null,
      lifetime:
        !key.duration_days ||
        key.duration_days === 0
    });
  }
);

// ==============================
// ADMIN LOGIN
// ==============================

app.post(
  "/api/admin/login",
  (req, res) => {

    const key =
      String(req.body.key || "").trim();

    if (key !== ADMIN_KEY) {
      return res.status(401).json({
        error: "Invalid admin key"
      });
    }

    const token =
      crypto.randomBytes(32).toString("hex");

    adminSessions.add(token);

    res.json({
      success: true,
      token
    });
  }
);

// ==============================
// ADMIN KEY LIST
// ==============================

app.get(
  "/api/admin/keys",
  adminAuth,
  (req, res) => {

    const keys = readKeys();

    const now = Date.now();

    const active =
      keys.filter(key => {

        if (key.revoked) {
          return false;
        }

        if (!key.expires_at) {
          return true;
        }

        return (
          new Date(
            key.expires_at
          ).getTime() > now
        );
      });

    const users =
      keys.filter(
        key => key.activated_at
      );

    res.json({

      stats: {
        total: keys.length,
        active: active.length,
        users: users.length
      },

      keys: keys.map(key => {

        let status = "ACTIVE";

        if (key.revoked) {
          status = "REVOKED";
        }

        else if (
          key.expires_at &&
          new Date(
            key.expires_at
          ).getTime() <= now
        ) {
          status = "EXPIRED";
        }

        return {
          id: key.id,
          key: key.key,
          duration_days:
            key.duration_days,
          activated_at:
            key.activated_at,
          expires_at:
            key.expires_at,
          status
        };

      })
    });
  }
);

// ==============================
// GENERATE KEYS
// ==============================

app.post(
  "/api/admin/generate",
  adminAuth,
  (req, res) => {

    let days =
      Number(req.body.days || 0);

    let quantity =
      Number(req.body.quantity || 1);

    if (!Number.isFinite(days)) {
      return res.status(400).json({
        error: "Invalid duration"
      });
    }

    quantity =
      Math.floor(quantity);

    if (quantity < 1) {
      quantity = 1;
    }

    if (quantity > 100) {
      quantity = 100;
    }

    const keys = readKeys();

    const generated = [];

    for (
      let i = 0;
      i < quantity;
      i++
    ) {

      const newKey = {

        id:
          crypto.randomUUID(),

        key:
          generateKey(),

        duration_days:
          days > 0 ? days : 0,

        activated_at:
          null,

        expires_at:
          null,

        revoked:
          false,

        created_at:
          new Date().toISOString()

      };

      keys.push(newKey);

      generated.push(
        newKey.key
      );
    }

    saveKeys(keys);

    res.json({
      success: true,
      keys: generated
    });
  }
);

// ==============================
// REVOKE KEY
// ==============================

app.post(
  "/api/admin/revoke/:id",
  adminAuth,
  (req, res) => {

    const keys = readKeys();

    const index =
      keys.findIndex(
        key =>
          key.id === req.params.id
      );

    if (index === -1) {
      return res.status(404).json({
        error: "Key not found"
      });
    }

    keys[index].revoked = true;

    saveKeys(keys);

    res.json({
      success: true
    });
  }
);

// ==============================
// MOBILECONFIG
// ==============================

app.get(
  "/nextra.mobileconfig",
  (req, res) => {

    const baseUrl =
      process.env.RENDER_EXTERNAL_URL ||
      `${req.protocol}://${req.get("host")}`;

    const url =
      baseUrl.replace(/\/$/, "");

    const profile = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">

<plist version="1.0">
<dict>

<key>PayloadContent</key>
<array>

<dict>

<key>FullScreen</key>
<true/>

<key>IsRemovable</key>
<true/>

<key>Label</key>
<string>NEXTRA</string>

<key>PayloadDescription</key>
<string>NEXTRA Web App</string>

<key>PayloadDisplayName</key>
<string>NEXTRA</string>

<key>PayloadIdentifier</key>
<string>com.nextra.webclip</string>

<key>PayloadOrganization</key>
<string>NEXTRA</string>

<key>PayloadType</key>
<string>com.apple.webClip.managed</string>

<key>PayloadUUID</key>
<string>7D4F2A9C-7A4D-4F5B-9C4D-1A8A2F3E7B11</string>

<key>PayloadVersion</key>
<integer>1</integer>

<key>URL</key>
<string>${url}/</string>

</dict>

</array>

<key>PayloadDisplayName</key>
<string>NEXTRA</string>

<key>PayloadIdentifier</key>
<string>com.nextra.profile</string>

<key>PayloadOrganization</key>
<string>NEXTRA</string>

<key>PayloadRemovalDisallowed</key>
<false/>

<key>PayloadType</key>
<string>Configuration</string>

<key>PayloadUUID</key>
<string>9A3B8F1C-2D6E-45F7-AB8D-5C1E3F7A9B20</string>

<key>PayloadVersion</key>
<integer>1</integer>

</dict>
</plist>`;

    res.setHeader(
      "Content-Type",
      "application/x-apple-aspen-config"
    );

    res.setHeader(
      "Content-Disposition",
      'inline; filename="NEXTRA.mobileconfig"'
    );

    res.send(profile);
  }
);

// ==============================
// API 404
// ==============================

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      error:
        "API endpoint not found"
    });
  }
);

// ==============================
// START
// ==============================

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `NEXTRA running on port ${PORT}`
    );
  }
);
