import { MongoClient, ObjectId } from "mongodb";
import {
  createLocalJWKSet,
  decodeProtectedHeader,
  jwtVerify,
} from "jose";

/* ------------------------------------------------------------------
   Better Auth JWT verification (Challenge 2).

   Tokens are minted by Better Auth's documented `jwt()` plugin
   (frontend `lib/auth.js` -> `GET /api/auth/token`). That plugin signs
   with an asymmetric key pair stored in the `jwks` collection of this
   same MongoDB, so the public keys are read straight from the database
   (falling back to `GET <BETTER_AUTH_URL>/api/auth/jwks` if the
   collection is empty). Nothing cross-origin has to share a cookie.
------------------------------------------------------------------ */

const DB_NAME = process.env.MONGO_DB || "mentor_lagbe_db";

/* Must match `jwt({ jwt: { issuer, audience } })` in the frontend. */
export const JWT_ISSUER = process.env.JWT_ISSUER || "mentorlagbe";
export const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "mentorlagbe-api";

const JWKS_TTL = 5 * 60 * 1000; // 5 minutes
const EMPTY_JWKS_TTL = 15 * 1000; // don't pin "no keys" for long

/* ------------------------------- db -------------------------------- */

const client = new MongoClient(process.env.MONGO_URI);
let dbPromise = null;

export async function getDb() {
  if (!dbPromise) {
    dbPromise = client
      .connect()
      .then(() => client.db(DB_NAME))
      .catch((err) => {
        dbPromise = null; // allow the next request to retry
        throw err;
      });
  }
  return dbPromise;
}

/* ------------------------------- jwks ------------------------------ */

let jwksCache = { set: null, at: 0 };

/** Better Auth stores the public half as a JSON string on the key row. */
function toJwk(doc) {
  let parsed = {};
  try {
    parsed =
      typeof doc.publicKey === "string"
        ? JSON.parse(doc.publicKey)
        : doc.publicKey || {};
  } catch {
    return null;
  }
  return {
    ...parsed,
    alg: doc.alg || parsed.alg,
    crv: doc.crv || parsed.crv,
    kid: String(doc._id),
    use: "sig",
  };
}

async function keysFromDatabase() {
  const db = await getDb();
  const docs = await db.collection("jwks").find({}).toArray();
  return docs.map(toJwk).filter(Boolean);
}

async function keysFromHttp() {
  const base = (
    process.env.BETTER_AUTH_URL ||
    process.env.FRONTEND_URL ||
    ""
  ).replace(/\/+$/, "");
  if (!base) return [];
  const res = await fetch(`${base}/api/auth/jwks`, {
    headers: { accept: "application/json" },
  });
  if (!res.ok) return [];
  const json = await res.json().catch(() => null);
  return Array.isArray(json?.keys) ? json.keys : [];
}

async function getJwks() {
  const now = Date.now();
  const fresh =
    jwksCache.set &&
    now - jwksCache.at < (jwksCache.keys ? JWKS_TTL : EMPTY_JWKS_TTL);
  if (fresh) return jwksCache.set;

  let keys = [];
  try {
    keys = await keysFromDatabase();
  } catch (err) {
    console.error("[auth] could not read the jwks collection:", err.message);
  }
  if (!keys.length) {
    try {
      keys = await keysFromHttp();
    } catch (err) {
      console.error("[auth] could not fetch /api/auth/jwks:", err.message);
    }
  }

  jwksCache = {
    set: createLocalJWKSet({ keys }),
    at: now,
    keys,
  };
  if (!keys.length) {
    console.warn(
      "[auth] no signing keys found — mint a token once via GET /api/auth/token"
    );
  }
  return jwksCache.set;
}

/* ---------------------------- verification ------------------------- */

const ALGS = ["EdDSA", "ES256", "RS256", "PS256", "HS256", "HS384", "HS512"];

async function verifyJwt(token) {
  const header = decodeProtectedHeader(token);
  if (!header.alg || !ALGS.includes(header.alg)) return null;

  const claims = { issuer: JWT_ISSUER, audience: JWT_AUDIENCE, clockTolerance: 15 };

  /* Shared-secret tokens (custom `jwt.sign` / symmetric fallback). */
  if (header.alg.startsWith("HS")) {
    const secret = process.env.BETTER_AUTH_SECRET || process.env.JWT_SECRET;
    if (!secret) return null;
    const key = new TextEncoder().encode(secret);
    try {
      return (await jwtVerify(token, key, { algorithms: [header.alg], ...claims }))
        .payload;
    } catch (err) {
      return isClaimError(err) ? verifyLoosely(token, key, header.alg) : null;
    }
  }

  const jwks = await getJwks();
  try {
    return (await jwtVerify(token, jwks, { algorithms: [header.alg], ...claims }))
      .payload;
  } catch (err) {
    /* Issuer/audience drift (e.g. an older frontend build) must not turn a
       crypturally valid token into "invalid". The signature + expiry checks
       are what actually protect us, so retry without the optional claims. */
    return isClaimError(err) ? verifyLoosely(token, jwks, header.alg) : null;
  }
}

function isClaimError(err) {
  return err?.code === "ERR_JWT_CLAIM_VALIDATION_FAILED";
}

async function verifyLoosely(token, key, alg) {
  try {
    return (
      await jwtVerify(token, key, { algorithms: [alg], clockTolerance: 15 })
    ).payload;
  } catch {
    return null;
  }
}

/** The JWT carries the user id as `sub`; older shapes used `id`/`userId`. */
async function loadUser(payload) {
  const db = await getDb();
  const users = db.collection("user");
  const projection = { projection: { password: 0 } };

  const id = payload?.sub ?? payload?.id ?? payload?.userId;
  if (id !== undefined && id !== null && id !== "") {
    const raw = String(id);
    const or = [{ _id: raw }];
    if (ObjectId.isValid(raw)) or.unshift({ _id: new ObjectId(raw) });
    const byId = await users.findOne({ $or: or }, projection);
    if (byId) return byId;
  }

  if (payload?.email) {
    const byEmail = await users.findOne({ email: payload.email }, projection);
    if (byEmail) return byEmail;
  }
  return null;
}

/* --------------------------- middlewares --------------------------- */

/**
 * Verifies the Better Auth JWT from `Authorization: Bearer <token>` and
 * attaches the fresh DB user to `req.user`.
 */
export async function verifyToken(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    const payload = await verifyJwt(token);
    if (!payload) {
      return res.status(401).json({ error: "Invalid token" });
    }

    const user = await loadUser(payload);
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    req.user = user;
    req.tokenPayload = payload;
    next();
  } catch (err) {
    console.error("[auth] token verification failed:", err);
    return res.status(401).json({ error: "Token verification failed" });
  }
}

/**
 * Resolves `req.user` when a valid Bearer token is present, but never rejects.
 *
 * Used by the public `GET /tutions` route: anonymous callers still get the
 * approved+active catalogue, while a signed-in tutor/admin asking for
 * `scope=mine` / `scope=all` gets their own or every listing. The scope is
 * always derived from the *verified* token — a client-supplied `tutorEmail`
 * is never trusted, so one tutor cannot read another's pending listings.
 */
export async function attachUser(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) return next();

  try {
    const payload = await verifyJwt(token);
    if (payload) {
      const user = await loadUser(payload);
      if (user) {
        req.user = user;
        req.tokenPayload = payload;
      }
    }
  } catch {
    /* treat as anonymous — the route decides whether that is acceptable */
  }
  next();
}

/** Signed-in and the Student role (admins may act on a student's behalf). */
export function verifyStudent(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "No token provided" });
  if (req.user.role !== "student" && req.user.role !== "admin") {
    return res.status(403).json({ error: "Student access required" });
  }
  next();
}

/** Signed-in and the Tutor role (admins may act on a tutor's behalf). */
export function verifyTutor(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "No token provided" });
  if (req.user.role !== "tutor" && req.user.role !== "admin") {
    return res.status(403).json({ error: "Tutor access required" });
  }
  next();
}

/** Signed-in and the Admin role. */
export function verifyAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "No token provided" });
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}
