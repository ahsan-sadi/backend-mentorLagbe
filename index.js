import express from "express";
import { ObjectId } from "mongodb";
import cors from "cors";
import "dotenv/config";

import {
  verifyToken,
  verifyStudent,
  verifyTutor,
  verifyAdmin,
  attachUser,
  getDb,
} from "./middlewares.js";

const app = express();

/* --- CORS -----------------------------------------------------------
   The Next.js app lives on another origin (and every Vercel preview
   deployment gets its own), so accept a comma-separated allow-list:
     FRONTEND_URLS=http://localhost:3000,https://mentorlagbe.vercel.app
   `*` cannot be used together with credentials, hence the explicit list
   plus an optional `*.vercel.app` escape hatch for preview builds. */
const allowedOrigins = (
  process.env.FRONTEND_URLS ||
  process.env.FRONTEND_URL ||
  "http://localhost:3000"
)
  .split(",")
  .map((origin) => origin.trim().replace(/\/+$/, ""))
  .filter(Boolean);

const corsOptions = {
  origin(origin, callback) {
    /* server-to-server / curl (no Origin header) and explicit allow-list */
    if (!origin) return callback(null, true);
    const clean = origin.replace(/\/+$/, "");
    const allowed =
      allowedOrigins.includes(clean) ||
      (process.env.ALLOW_VERCEL_PREVIEWS === "true" &&
        /^https:\/\/[\w-]+\.vercel\.app$/.test(clean));
    callback(null, allowed);
  },
  credentials: true,
  methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Accept"],
  maxAge: 600,
};

app.use(cors(corsOptions));
/* Banner images can fall back to a compressed data-URL when ImgBB is not
   configured, so the default 100 KB JSON limit is too small. */
app.use(express.json({ limit: "2mb" }));

// Database connection (shared with the auth middlewares).
// A missing/typo'd MONGO_URI used to crash at import time with an opaque
// stack trace — surface the actual cause in the Vercel logs instead.
let database;
try {
  database = await getDb();
  if (database) {
    console.log("[startup] Connected to MongoDB.");
  }
} catch (err) {
  console.error(
    "[startup] Could not connect to MongoDB.",
    "Set MONGO_URI on this deployment.",
    err?.message || err,
  );
  throw err;
}
const usersCollection = database.collection("user");
const tutionsCollection = database.collection("tutions");
const applicationsCollection = database.collection("applications");
const paymentsCollection = database.collection("payments");
const bookmarksCollection = database.collection("bookmarks");
const reviewsCollection = database.collection("reviews");

// Public endpoints (no auth required)
app.get("/", (req, res) => {
  res.send("Hello, MentorLagbe!");
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "mentorlagbe-api",
    time: new Date().toISOString(),
  });
});

/* ------------------------------------------------------------------
   DEPRECATED — the JWT is now issued by Better Auth itself.

   The old implementation tried to read the `better-auth.session_token`
   cookie on this cross-origin API. That cookie is host-only and
   SameSite=Lax, so the browser never sent it here, and even when it did
   arrive it is an opaque session token rather than a JWT — which is why
   every protected call failed with "No token provided" / "Invalid token".

   Tokens now come from the Better Auth `jwt()` plugin, same-origin:
       GET <frontend>/api/auth/token   ->  { "token": "<jwt>" }
   and are sent back as `Authorization: Bearer <jwt>`, verified by
   `verifyToken` in ./middlewares.js against the plugin's JWKS.
------------------------------------------------------------------ */
app.get("/auth/token", (req, res) => {
  res.status(410).json({
    error:
      "This endpoint has moved. Call GET <BETTER_AUTH_URL>/api/auth/token " +
      "(Better Auth JWT plugin) from the same origin as the frontend, then " +
      "send the result as Authorization: Bearer <token>.",
  });
});

// Tutions - Public browse with search, filter, pagination
app.get("/tutions", attachUser, async (req, res) => {
  try {
    const {
      q, // search query (title / subject / tutor)
      subject,
      classLevel,
      mode,
      page = 1,
      limit,
      sortBy = "createdAt",
      sortOrder = "desc",
      /* scope:
         (absent) public browse — approved + active only
         "mine"   signed-in tutor/admin — their own listings, every status
         "all"    signed-in admin — every listing, every status */
      scope,
    } = req.query;

    let query;
    let scoped = false;
    let defaultLimit = 6;

    if (scope === "mine") {
      if (!req.user) {
        return res.status(401).json({ error: "No token provided" });
      }
      if (req.user.role !== "tutor" && req.user.role !== "admin") {
        return res.status(403).json({ error: "Tutor access required" });
      }
      /* Identity comes from the verified token, never from the query string. */
      query = { tutorEmail: req.user.email };
      scoped = true;
      defaultLimit = 200;
    } else if (scope === "all") {
      if (!req.user) {
        return res.status(401).json({ error: "No token provided" });
      }
      if (req.user.role !== "admin") {
        return res.status(403).json({ error: "Admin access required" });
      }
      query = {};
      scoped = true;
      defaultLimit = 200;
    } else {
      query = {
        approvalStatus: "approved",
        isActive: true,
      };
    }

    /* Search by title, subject, or tutorName. The input is escaped first so a
       stray "(" or "\\" can't throw inside RegExp and 500 the page. */
    const search = String(q || "").trim();
    if (search) {
      const searchRegex = new RegExp(
        search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
        "i",
      );
      query.$or = [
        { title: searchRegex },
        { subject: searchRegex },
        { tutorName: searchRegex },
      ];
    }

    // Filter by subject
    if (subject) {
      query.subject = String(subject);
    }

    // Filter by class level
    if (classLevel) {
      query.classLevel = String(classLevel);
    }

    // Filter by mode (Online/Offline)
    if (mode) {
      query.mode = String(mode);
    }

    const pageNum = Math.max(1, parseInt(page) || 1);
    /* Dashboards pull their whole list in one request (they filter and sort
       client-side); the public browse page stays paginated at a sane size. */
    const limitNum = Math.min(
      scoped ? 500 : 50,
      Math.max(1, parseInt(limit) || defaultLimit),
    );
    const skip = (pageNum - 1) * limitNum;

    const sort = {};
    sort[
      ["createdAt", "monthlyFee", "title", "rating", "daysPerWeek"].includes(
        sortBy,
      )
        ? sortBy
        : "createdAt"
    ] = sortOrder === "asc" ? 1 : -1;

    const [tuitions, total] = await Promise.all([
      tutionsCollection
        .find(query)
        .sort(sort)
        .skip(skip)
        .limit(limitNum)
        .toArray(),
      tutionsCollection.countDocuments(query),
    ]);

    res.json({
      tuitions,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        totalPages: Math.ceil(total / limitNum),
      },
    });
  } catch (err) {
    console.error("Error fetching tuitions:", err);
    res.status(500).json({ error: "Failed to fetch tuitions" });
  }
});

// Count tuitions — no filter = every listing, `?tutorEmail=` = one tutor's posts
app.get("/tutions/count", async (req, res) => {
  try {
    const params = {};
    if (req.query.tutorEmail) {
      params.tutorEmail = String(req.query.tutorEmail);
    }
    const count = await tutionsCollection.countDocuments(params);
    res.json({ count });
  } catch (err) {
    res.status(500).json({ error: "Failed to count tuitions" });
  }
});

// Get category stats — count of approved active tuitions per subject
app.get("/tutions/categories", async (req, res) => {
  try {
    const pipeline = [
      { $match: { approvalStatus: "approved", isActive: true } },
      { $group: { _id: "$subject", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $project: { subject: "$_id", count: 1, _id: 0 } },
    ];
    const categories = await tutionsCollection.aggregate(pipeline).toArray();
    res.json(categories);
  } catch (err) {
    console.error("Error fetching category stats:", err);
    res.status(500).json({ error: "Failed to fetch category stats" });
  }
});

// Fetch a single tution (public)
app.get("/tutions/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid tution id" });
    }
    const tuition = await tutionsCollection.findOne({
      _id: new ObjectId(id),
    });
    if (!tuition) {
      return res.status(404).json({ error: "Tution not found" });
    }
    res.json(tuition);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch tuition" });
  }
});

// Protected endpoints (require auth)
app.post("/tutions", verifyToken, verifyTutor, async (req, res) => {
  try {
    const body = { ...req.body };
    /* Never let the client pick these — they come from the verified token
       and the server's own approval workflow. */
    delete body.tutorEmail;
    delete body.tutorName;
    delete body.tutorPlan;
    delete body.approvalStatus;
    delete body.isActive;
    delete body.createdAt;
    delete body._id;

    const tuitionData = {
      ...body,
      tutorEmail: req.user.email,
      tutorName: req.user.name,
      tutorPlan: req.user.plan || "free",
      approvalStatus: "pending",
      isActive: true,
      createdAt: new Date().toISOString(),
    };
    const result = await tutionsCollection.insertOne(tuitionData);
    res.status(201).json({
      ...tuitionData,
      _id: result.insertedId,
      insertedId: result.insertedId,
    });
  } catch (err) {
    console.error("Error creating tuition:", err);
    res.status(500).json({ error: "Failed to create tuition" });
  }
});

// Update a tution (edit a listing, pause/activate, admin approval)
app.patch("/tutions/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid tution id" });
    }

    const tuition = await tutionsCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!tuition) {
      return res.status(404).json({ error: "Tution not found" });
    }

    // Check permissions: tutor can edit own, admin can edit any
    if (req.user.role !== "admin" && tuition.tutorEmail !== req.user.email) {
      return res
        .status(403)
        .json({ error: "Not authorized to edit this tuition" });
    }

    const { _id, ...updates } = req.body;
    // Prevent changing tutorEmail, tutorName, createdAt
    delete updates.tutorEmail;
    delete updates.tutorName;
    delete updates.createdAt;

    /* Approval and plan are server/admin concerns: a tutor must not be able
       to approve their own listing or upgrade their own plan in the same
       request that edits the copy. */
    if (req.user.role !== "admin") {
      delete updates.approvalStatus;
      delete updates.tutorPlan;
      delete updates.tutorEmail;
      delete updates.tutorName;
    }

    const result = await tutionsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updates },
    );

    if (!result.matchedCount) {
      return res.status(404).json({ error: "Tution not found" });
    }

    const updatedTuition = await tutionsCollection.findOne({
      _id: new ObjectId(id),
    });
    res.json(updatedTuition);
  } catch (err) {
    res.status(500).json({ error: "Failed to update tuition" });
  }
});

// Delete a tution (and every application filed against it)
app.delete("/tutions/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid tution id" });
    }

    const tuition = await tutionsCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!tuition) {
      return res.status(404).json({ error: "Tution not found" });
    }

    // Check permissions: tutor can delete own, admin can delete any
    if (req.user.role !== "admin" && tuition.tutorEmail !== req.user.email) {
      return res
        .status(403)
        .json({ error: "Not authorized to delete this tuition" });
    }

    const result = await tutionsCollection.deleteOne({
      _id: new ObjectId(id),
    });

    if (!result.deletedCount) {
      return res.status(404).json({ error: "Tution not found" });
    }

    await applicationsCollection.deleteMany({ tuitionId: id });
    await bookmarksCollection.deleteMany({ tuitionId: id });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "Failed to delete tuition" });
  }
});

// Applications --------------------------------------------------------------

// Get all applications (admin only)
// Users (admin) --------------------------------------------------------

/* Every account. The `password` field is never selected — this is the only
   route that returns user records wholesale. */
app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const users = await usersCollection
      .find({}, { projection: { password: 0 } })
      .sort({ createdAt: -1 })
      .toArray();
    res.json(users);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

const ALLOWED_ROLES = ["student", "tutor", "admin"];
const ALLOWED_PLANS = ["free", "pro"];

/* Admin edits a user's role or plan. Identity fields (email, name, password)
   are deliberately not writable from here. */
app.patch("/users/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid user id" });
    }

    const { role, plan } = req.body;
    const updates = {};

    if (role !== undefined) {
      if (!ALLOWED_ROLES.includes(role)) {
        return res.status(400).json({ error: "Invalid role" });
      }
      /* Demoting yourself can lock the last admin out of the platform. */
      if (String(req.user._id) === String(id) && role !== "admin") {
        return res.status(400).json({ error: "You cannot change your own role" });
      }
      updates.role = role;
    }

    if (plan !== undefined) {
      if (!ALLOWED_PLANS.includes(plan)) {
        return res.status(400).json({ error: "Invalid plan" });
      }
      updates.plan = plan;
    }

    if (!Object.keys(updates).length) {
      return res.status(400).json({ error: "Nothing to update" });
    }
    updates.updatedAt = new Date().toISOString();

    const result = await usersCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updates },
    );
    if (!result.matchedCount) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = await usersCollection.findOne(
      { _id: new ObjectId(id) },
      { projection: { password: 0 } },
    );
    res.json(user);
  } catch (err) {
    console.error("Error updating user:", err);
    res.status(500).json({ error: "Failed to update user" });
  }
});

// Applications ---------------------------------------------------------

app.get("/applications", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const cursor = applicationsCollection.find({});
    const result = await cursor.toArray();
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch applications" });
  }
});

// Get applications for current user (student or tutor)
app.get("/applications/my", verifyToken, async (req, res) => {
  try {
    const query = {};
    if (req.user.role === "student") {
      query.studentEmail = req.user.email;
    } else if (req.user.role === "tutor") {
      query.tutorEmail = req.user.email;
    }
    const cursor = applicationsCollection.find(query);
    const result = await cursor.toArray();
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch applications" });
  }
});

// Fetch one application — the applicant, the tutor who owns the listing, or an
// admin. Registered after `/applications/my` so the literal path wins.
app.get("/applications/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid application id" });
    }
    const application = await applicationsCollection.findOne({
      _id: new ObjectId(id),
    });
    if (!application) {
      return res.status(404).json({ error: "Application not found" });
    }

    const role = req.user.role;
    const isOwner =
      (role === "student" && application.studentEmail === req.user.email) ||
      (role === "tutor" && application.tutorEmail === req.user.email) ||
      role === "admin";

    if (!isOwner) {
      return res.status(403).json({ error: "Not allowed to view this application" });
    }

    res.json(application);
  } catch (err) {
    console.error("Error fetching application:", err);
    res.status(500).json({ error: "Failed to fetch application" });
  }
});

// A student applies to a tuition
app.post("/applications", verifyToken, verifyStudent, async (req, res) => {
  try {
    const {
      tuitionId,
      studentName,
      studentPhone,
      preferredSchedule,
      studentNote,
    } = req.body;

    if (!tuitionId) {
      return res.status(400).json({ error: "tuitionId is required" });
    }
    if (!ObjectId.isValid(tuitionId)) {
      return res.status(400).json({ error: "Invalid tution id" });
    }

    const tuition = await tutionsCollection.findOne({
      _id: new ObjectId(tuitionId),
    });

    if (!tuition) {
      return res.status(404).json({ error: "Tution not found" });
    }

    if (tuition.approvalStatus !== "approved") {
      return res
        .status(400)
        .json({ error: "This tuition is not open for applications." });
    }

    if (tuition.isActive === false) {
      return res
        .status(400)
        .json({ error: "This tuition is closed for applications." });
    }

    const existing = await applicationsCollection.findOne({
      tuitionId,
      studentEmail: req.user.email,
    });

    if (existing) {
      return res
        .status(409)
        .json({ error: "You have already applied for this tuition." });
    }

    const application = {
      tuitionId,
      tuitionTitle: tuition.title || "",
      subject: tuition.subject || "",
      monthlyFee: tuition.monthlyFee ?? 0,
      tutorEmail: tuition.tutorEmail || "",
      studentName: studentName || req.user.name,
      studentEmail: req.user.email,
      studentPhone: studentPhone || "",
      preferredSchedule: preferredSchedule || "",
      studentNote: studentNote || "",
      status: "pending",
      appliedAt: new Date().toISOString(),
    };

    const result = await applicationsCollection.insertOne(application);
    res.status(201).json({ ...application, _id: result.insertedId });
  } catch (err) {
    res.status(500).json({ error: "Failed to create application" });
  }
});

// Update an application (tutor accepts/rejects, admin can update any)
app.patch("/applications/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid application id" });
    }

    const application = await applicationsCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!application) {
      return res.status(404).json({ error: "Application not found" });
    }

    // Check permissions
    const isTutor =
      req.user.role === "tutor" && application.tutorEmail === req.user.email;
    const isAdmin = req.user.role === "admin";

    if (!isTutor && !isAdmin) {
      return res
        .status(403)
        .json({ error: "Not authorized to update this application" });
    }

    /* Only the decision itself is mutable — a tutor/admin must not be able to
       re-attribute an application to another student or tuition. */
    const { _id, tuitionId, appliedAt, ...rest } = req.body;
    const updates = {};
    if (rest.status !== undefined) updates.status = rest.status;
    if (rest.adminNote !== undefined) updates.adminNote = rest.adminNote;

    const result = await applicationsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updates },
    );

    if (!result.matchedCount) {
      return res.status(404).json({ error: "Application not found" });
    }

    const updatedApplication = await applicationsCollection.findOne({
      _id: new ObjectId(id),
    });
    res.json(updatedApplication);
  } catch (err) {
    res.status(500).json({ error: "Failed to update application" });
  }
});

// Delete an application (student cancels own, admin can delete any)
app.delete("/applications/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid application id" });
    }

    const application = await applicationsCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!application) {
      return res.status(404).json({ error: "Application not found" });
    }

    // Check permissions
    const isStudent =
      req.user.role === "student" &&
      application.studentEmail === req.user.email;
    const isAdmin = req.user.role === "admin";

    if (!isStudent && !isAdmin) {
      return res
        .status(403)
        .json({ error: "Not authorized to delete this application" });
    }

    const result = await applicationsCollection.deleteOne({
      _id: new ObjectId(id),
    });

    if (!result.deletedCount) {
      return res.status(404).json({ error: "Application not found" });
    }

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "Failed to delete application" });
  }
});

// Bookmarks / Saved Tuitions ------------------------------------------------

// Get user's bookmarks
app.get("/bookmarks", verifyToken, verifyStudent, async (req, res) => {
  try {
    const bookmarks = await bookmarksCollection
      .find({ studentEmail: req.user.email })
      .sort({ createdAt: -1 })
      .toArray();

    // Populate tuition details
    const tuitionIds = bookmarks.map((b) => new ObjectId(b.tuitionId));
    const tuitions = await tutionsCollection
      .find({ _id: { $in: tuitionIds } })
      .toArray();

    const tuitionMap = new Map(tuitions.map((t) => [t._id.toString(), t]));
    const populated = bookmarks.map((b) => ({
      ...b,
      tuition: tuitionMap.get(b.tuitionId),
    }));

    res.json(populated);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch bookmarks" });
  }
});

// Add bookmark
app.post("/bookmarks", verifyToken, verifyStudent, async (req, res) => {
  try {
    const { tuitionId } = req.body;

    if (!tuitionId || !ObjectId.isValid(tuitionId)) {
      return res.status(400).json({ error: "Valid tuitionId is required" });
    }

    const tuition = await tutionsCollection.findOne({
      _id: new ObjectId(tuitionId),
    });

    if (!tuition) {
      return res.status(404).json({ error: "Tuition not found" });
    }

    const existing = await bookmarksCollection.findOne({
      studentEmail: req.user.email,
      tuitionId,
    });

    if (existing) {
      return res.status(409).json({ error: "Already bookmarked" });
    }

    const bookmark = {
      studentEmail: req.user.email,
      tuitionId,
      createdAt: new Date().toISOString(),
    };

    const result = await bookmarksCollection.insertOne(bookmark);
    res.status(201).json({ ...bookmark, _id: result.insertedId });
  } catch (err) {
    res.status(500).json({ error: "Failed to add bookmark" });
  }
});

// Remove bookmark
app.delete(
  "/bookmarks/:tuitionId",
  verifyToken,
  verifyStudent,
  async (req, res) => {
    try {
      const { tuitionId } = req.params;

      const result = await bookmarksCollection.deleteOne({
        studentEmail: req.user.email,
        tuitionId,
      });

      if (!result.deletedCount) {
        return res.status(404).json({ error: "Bookmark not found" });
      }

      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: "Failed to remove bookmark" });
    }
  },
);

// Check if tuition is bookmarked
app.get(
  "/bookmarks/check/:tuitionId",
  verifyToken,
  verifyStudent,
  async (req, res) => {
    try {
      const { tuitionId } = req.params;

      const bookmark = await bookmarksCollection.findOne({
        studentEmail: req.user.email,
        tuitionId,
      });

      res.json({ bookmarked: !!bookmark });
    } catch (err) {
      res.status(500).json({ error: "Failed to check bookmark" });
    }
  },
);

// Reviews / Ratings ---------------------------------------------------------

// Get reviews for a tuition
app.get("/reviews/tuition/:tuitionId", async (req, res) => {
  try {
    const { tuitionId } = req.params;

    const reviews = await reviewsCollection
      .find({ tuitionId })
      .sort({ createdAt: -1 })
      .toArray();

    // Calculate average rating
    const avgRating =
      reviews.length > 0
        ? reviews.reduce((sum, r) => sum + r.rating, 0) / reviews.length
        : 0;

    res.json({
      reviews,
      stats: {
        average: Math.round(avgRating * 10) / 10,
        count: reviews.length,
      },
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch reviews" });
  }
});

// Create review (only students with accepted application)
app.post("/reviews", verifyToken, verifyStudent, async (req, res) => {
  try {
    const { tuitionId, rating, comment } = req.body;

    if (!tuitionId || !rating) {
      return res
        .status(400)
        .json({ error: "tuitionId and rating are required" });
    }

    if (rating < 1 || rating > 5) {
      return res.status(400).json({ error: "Rating must be between 1 and 5" });
    }

    // Check if student has an accepted application for this tuition
    const application = await applicationsCollection.findOne({
      tuitionId,
      studentEmail: req.user.email,
      status: "accepted",
    });

    if (!application) {
      return res
        .status(403)
        .json({
          error: "You can only review tuitions you have been accepted to",
        });
    }

    // Check if already reviewed
    const existing = await reviewsCollection.findOne({
      tuitionId,
      studentEmail: req.user.email,
    });

    if (existing) {
      return res
        .status(409)
        .json({ error: "You have already reviewed this tuition" });
    }

    const review = {
      tuitionId,
      tuitionTitle: application.tuitionTitle,
      studentEmail: req.user.email,
      studentName: req.user.name,
      rating: Number(rating),
      comment: comment || "",
      createdAt: new Date().toISOString(),
    };

    const result = await reviewsCollection.insertOne(review);
    res.status(201).json({ ...review, _id: result.insertedId });
  } catch (err) {
    res.status(500).json({ error: "Failed to create review" });
  }
});

// Update review (student can update own)
app.patch("/reviews/:id", verifyToken, verifyStudent, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid review id" });
    }

    const review = await reviewsCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!review) {
      return res.status(404).json({ error: "Review not found" });
    }

    if (review.studentEmail !== req.user.email) {
      return res
        .status(403)
        .json({ error: "Not authorized to update this review" });
    }

    const { rating, comment } = req.body;
    const updates = {};

    if (rating !== undefined) {
      if (rating < 1 || rating > 5) {
        return res
          .status(400)
          .json({ error: "Rating must be between 1 and 5" });
      }
      updates.rating = Number(rating);
    }

    if (comment !== undefined) {
      updates.comment = comment;
    }

    const result = await reviewsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updates },
    );

    if (!result.matchedCount) {
      return res.status(404).json({ error: "Review not found" });
    }

    const updatedReview = await reviewsCollection.findOne({
      _id: new ObjectId(id),
    });
    res.json(updatedReview);
  } catch (err) {
    res.status(500).json({ error: "Failed to update review" });
  }
});

// Delete review (student can delete own, admin can delete any)
app.delete("/reviews/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid review id" });
    }

    const review = await reviewsCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!review) {
      return res.status(404).json({ error: "Review not found" });
    }

    const isOwner = review.studentEmail === req.user.email;
    const isAdmin = req.user.role === "admin";

    if (!isOwner && !isAdmin) {
      return res
        .status(403)
        .json({ error: "Not authorized to delete this review" });
    }

    const result = await reviewsCollection.deleteOne({
      _id: new ObjectId(id),
    });

    if (!result.deletedCount) {
      return res.status(404).json({ error: "Review not found" });
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete review" });
  }
});

// Seed endpoint (admin only) - for AI-generated data seeding
app.post("/admin/seed", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const count = parseInt(req.query.count) || 20;

    // This would be expanded with AI-generated data
    // For now, return a message
    res.json({
      message: "Seed endpoint ready. Implement AI data generation here.",
      requestedCount: count,
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to seed data" });
  }
});

export default app;

// Local development server
if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 8000;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}
