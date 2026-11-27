import { MongoClient, ObjectId } from "mongodb";
import { randomBytes, scryptSync } from "crypto";
import "dotenv/config";

/* Better Auth hashes passwords with scrypt (see @better-auth/utils/password):
   N=16384, r=16, p=1, dkLen=64, NFKC-normalized password, `salt:hash` hex. */
const SCRYPT_CONFIG = { N: 16384, r: 16, p: 1, dkLen: 64 };
function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const normalized = password.normalize("NFKC");
  const hash = scryptSync(normalized, salt, SCRYPT_CONFIG.dkLen, {
    N: SCRYPT_CONFIG.N,
    r: SCRYPT_CONFIG.r,
    p: SCRYPT_CONFIG.p,
    maxmem: 128 * SCRYPT_CONFIG.N * SCRYPT_CONFIG.r * 2,
  }).toString("hex");
  return `${salt}:${hash}`;
}

const client = new MongoClient(process.env.MONGO_URI);

const SUBJECTS = [
  "Mathematics", "Physics", "Chemistry", "Biology",
  "Programming", "English", "IELTS", "Bangla",
  "Economics", "ICT", "Accounting", "Business Studies",
];

const CLASS_LEVELS = [
  "Class 6-8", "Class 9-10", "Class 11-12",
  "Admission", "University",
];

const MODES = ["Online", "Offline"];

const LOCATIONS = [
  "Dhanmondi, Dhaka", "Gulshan, Dhaka", "Banani, Dhaka",
  "Uttara, Dhaka", "Mirpur, Dhaka", "Mohammadpur, Dhaka",
  "Chittagong", "Sylhet", "Rajshahi", "Khulna",
  "Online (Zoom)", "Online (Google Meet)", "Online (Teams)",
];

const TUTOR_NAMES = [
  "Dr. Ahmed Hassan", "Prof. Fatima Khan", "Md. Rahim Uddin",
  "Ayesha Rahman", "Karim Ahmed", "Nusrat Jahan",
  "Tanvir Islam", "Sadia Akter", "Rafiq Mahmud", "Farhana Begum",
  "Imran Hossain", "Tasnim Sultana", "Kamal Hossain", "Rina Parvin",
];

const STUDENT_NAMES = [
  "Arif Mahmud", "Samira Islam", "Hasan Ali", "Meherun Nesa",
  "Kamrul Hasan", "Tania Akter", "Rakib Ahmed", "Sultana Razia",
  "Naeem Uddin", "Farzana Begum", "Shakil Ahmed", "Mousumi Jahan",
];

const TUTOR_BIOS = [
  "Experienced tutor with 10+ years teaching Mathematics and Physics. PhD from BUET.",
  "Former university lecturer specializing in Chemistry and Biology. MSc from Dhaka University.",
  "Software engineer turned programming tutor. Expert in Python, JavaScript, and React.",
  "English language expert with IELTS 8.5 band score. 8 years coaching experience.",
  "Economics graduate from LSE. Specializes in HSC and university-level Economics.",
  "ICT teacher at a top school in Dhaka. Google Certified Educator.",
];

const STUDENT_BIOS = [
  "Looking for a patient tutor for HSC Physics and Chemistry.",
  "Need help with IELTS preparation, targeting 7.5+ band.",
  "University student struggling with Calculus and Linear Algebra.",
  "Class 10 student preparing for SSC exams in all science subjects.",
  "Want to learn Python programming from scratch for career change.",
];

const TUITION_TITLES = [
  "HSC {subject} Mastery Course",
  "SSC {subject} Complete Preparation",
  "University {subject} 1-on-1 Coaching",
  "{subject} for Admission Test Preparation",
  "Advanced {subject} Problem Solving",
  "{subject} Crash Course (3 Months)",
  "Foundation {subject} for Class {classLevel}",
  "Practical {subject} Lab Sessions",
];

const TUITION_DESCRIPTIONS = [
  "This comprehensive course covers the entire {subject} syllabus for {classLevel}. "
  + "Classes will focus on concept clarity, problem-solving techniques, and exam strategies. "
  + "Regular tests and feedback sessions included. {mode} classes available.",

  "Personalized {subject} tutoring tailored to your learning pace and style. "
  + "I use real-world examples to make complex topics easy to understand. "
  + "Weekly assignments and progress tracking. {mode} sessions via {location}.",

  "Intensive {subject} preparation for {classLevel} exams. "
  + "Covers all chapters with emphasis on important topics and previous year questions. "
  + "Mock tests every weekend. {mode} classes at {location}.",
];

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateTutor() {
  const name = randomItem(TUTOR_NAMES);
  const email = name.toLowerCase().replace(/[.\s]/g, "") + "@mentorlagbe.com";
  const phone = `+880 1${randomInt(3, 9)}${randomInt(10000000, 99999999)}`;
  return {
    name,
    email,
    password: hashPassword("password123"),
    phone,
    role: "tutor",
    plan: randomItem(["free", "pro"]),
    bio: randomItem(TUTOR_BIOS),
    image: `https://api.dicebear.com/9.x/notionists/svg?seed=${email}`,
    createdAt: new Date(Date.now() - randomInt(0, 365) * 24 * 60 * 60 * 1000).toISOString(),
  };
}

function generateStudent() {
  const name = randomItem(STUDENT_NAMES);
  const email = name.toLowerCase().replace(/[.\s]/g, "") + "@mentorlagbe.com";
  const phone = `+880 1${randomInt(3, 9)}${randomInt(10000000, 99999999)}`;
  return {
    name,
    email,
    password: hashPassword("password123"),
    phone,
    role: "student",
    plan: "free",
    bio: randomItem(STUDENT_BIOS),
    image: `https://api.dicebear.com/9.x/notionists/svg?seed=${email}`,
    createdAt: new Date(Date.now() - randomInt(0, 365) * 24 * 60 * 60 * 1000).toISOString(),
  };
}

function generateTuition(tutor) {
  const subject = randomItem(SUBJECTS);
  const classLevel = randomItem(CLASS_LEVELS);
  const mode = randomItem(MODES);
  const location = mode === "Online"
    ? randomItem(LOCATIONS.filter(l => l.startsWith("Online")))
    : randomItem(LOCATIONS.filter(l => !l.startsWith("Online")));

  const titleTemplate = randomItem(TUITION_TITLES);
  const title = titleTemplate
    .replace("{subject}", subject)
    .replace("{classLevel}", classLevel);

  const descTemplate = randomItem(TUITION_DESCRIPTIONS);
  const description = descTemplate
    .replace("{subject}", subject)
    .replace("{classLevel}", classLevel)
    .replace("{mode}", mode)
    .replace("{location}", location);

  const monthlyFee = randomInt(3000, 15000);
  const daysPerWeek = randomInt(2, 4);

  const scheduleOptions = [
    "Sat, Tue, Thu · 6:00 PM – 7:30 PM",
    "Sun, Wed, Fri · 5:00 PM – 6:30 PM",
    "Mon, Wed, Fri · 7:00 PM – 8:30 PM",
    "Sat, Mon, Wed · 4:00 PM – 5:30 PM",
  ];

  return {
    title,
    subject,
    classLevel,
    mode,
    location,
    monthlyFee,
    daysPerWeek,
    schedule: randomItem(scheduleOptions),
    description,
    bannerImage: `https://images.unsplash.com/photo-${randomInt(1000000000, 9999999999)}?w=800&q=80`,
    tutorEmail: tutor.email,
    tutorName: tutor.name,
    tutorPlan: tutor.plan,
    approvalStatus: randomItem(["approved", "approved", "approved", "pending"]), // 75% approved
    isActive: true,
    createdAt: new Date(Date.now() - randomInt(0, 180) * 24 * 60 * 60 * 1000).toISOString(),
  };
}

function generateApplication(student, tuition) {
  const statuses = ["pending", "accepted", "rejected"];
  const status = randomItem(statuses);

  return {
    tuitionId: tuition._id.toString(),
    tuitionTitle: tuition.title,
    subject: tuition.subject,
    monthlyFee: tuition.monthlyFee,
    tutorEmail: tuition.tutorEmail,
    studentName: student.name,
    studentEmail: student.email,
    studentPhone: student.phone,
    preferredSchedule: "Flexible, prefer evenings",
    studentNote: "I am very interested in this tuition and can commit to the schedule.",
    status,
    appliedAt: new Date(
      new Date(tuition.createdAt).getTime() + randomInt(1, 30) * 24 * 60 * 60 * 1000
    ).toISOString(),
  };
}

function generateReview(student, tuition) {
  return {
    tuitionId: tuition._id.toString(),
    tuitionTitle: tuition.title,
    studentEmail: student.email,
    studentName: student.name,
    rating: randomInt(3, 5),
    comment: randomItem([
      "Excellent tutor! Very clear explanations and patient teaching style.",
      "Helped me improve my grades significantly. Highly recommended!",
      "Great teaching methods and very responsive to questions.",
      "Professional and knowledgeable. Worth every penny.",
      "Made complex topics easy to understand. Thank you!",
    ]),
    createdAt: new Date(Date.now() - randomInt(0, 60) * 24 * 60 * 60 * 1000).toISOString(),
  };
}

function generateBookmark(student, tuition) {
  return {
    studentEmail: student.email,
    tuitionId: tuition._id.toString(),
    createdAt: new Date(
      new Date(tuition.createdAt).getTime() + randomInt(1, 10) * 24 * 60 * 60 * 1000
    ).toISOString(),
  };
}

async function seedDatabase() {
  try {
    await client.connect();
    console.log("Connected to MongoDB");

    const db = client.db("mentor_lagbe_db");
    const usersCollection = db.collection("user");
    const accountsCollection = db.collection("account");
    const tutionsCollection = db.collection("tutions");
    const applicationsCollection = db.collection("applications");
    const reviewsCollection = db.collection("reviews");
    const bookmarksCollection = db.collection("bookmarks");

    // Clear existing data (optional - comment out to keep existing)
    console.log("Clearing existing data...");
    await Promise.all([
      usersCollection.deleteMany({}),
      accountsCollection.deleteMany({}),
      tutionsCollection.deleteMany({}),
      applicationsCollection.deleteMany({}),
      reviewsCollection.deleteMany({}),
      bookmarksCollection.deleteMany({}),
      /* `session` / `verification` hang off `userId`, so clearing `user`
         without them leaves orphaned rows behind on every re-seed. */
      db.collection("session").deleteMany({}),
      db.collection("verification").deleteMany({}),
    ]);
    
    // Drop and recreate indexes to ensure clean state
    await usersCollection.dropIndexes().catch(() => {});
    /* `dropIndexes()` also removes Better Auth's unique email index; without
       it a duplicate sign-up silently succeeds and sign-in becomes ambiguous. */
    await usersCollection
      .createIndex({ email: 1 }, { unique: true, name: "user_email_uidx" })
      .catch((err) => console.warn("Could not recreate email index:", err.message));

    /* Better Auth (emailAndPassword) stores credentials in the `account`
       collection — NOT on the `user` document. Each user gets a paired
       credential account whose `password` is `salt:hash` (scrypt).
       `accountId` / `userId` are stored as strings (the adapter stringifies
       ObjectIds), which is what the sign-in lookup queries with. */
    const createUserWithAccount = async (userData, plainPassword) => {
      const now = new Date().toISOString();
      const userDoc = {
        ...userData,
        emailVerified: false,
        createdAt: now,
        updatedAt: now,
      };
      const { password: _omit, ...cleanUser } = userDoc;
      const result = await usersCollection.insertOne(cleanUser);
      const userId = result.insertedId.toString();
      await accountsCollection.insertOne({
        /* `accountId` is compared to the user's string `id` by Better Auth, so
           it stays a string. `userId` MUST be an ObjectId: the Mongo adapter
           converts the sign-in lookup value to an ObjectId, so a string stored
           here never matches and the seeded account cannot sign in. */
        accountId: userId,
        providerId: "credential",
        userId: result.insertedId,
        password: hashPassword(plainPassword),
        createdAt: now,
        updatedAt: now,
      });
      return { ...cleanUser, _id: result.insertedId };
    };

    // Create admin user
    const admin = await createUserWithAccount({
      name: "Admin User",
      email: "admin@mentorlagbe.com",
      phone: "+880 1711111111",
      role: "admin",
      plan: "pro",
      bio: "Platform administrator",
      image: "https://api.dicebear.com/9.x/notionists/svg?seed=admin",
    }, "password123");
    console.log("Created admin user");

    // Generate tutors
    console.log("Generating tutors...");
    const tutors = [];
    for (let i = 0; i < 15; i++) {
      const tutor = generateTutor();
      const { password, ...tutorData } = tutor;
      const created = await createUserWithAccount(tutorData, "password123");
      tutors.push(created);
    }
    console.log(`Created ${tutors.length} tutors`);

    // Generate students
    console.log("Generating students...");
    const students = [];
    for (let i = 0; i < 20; i++) {
      const student = generateStudent();
      const { password, ...studentData } = student;
      const created = await createUserWithAccount(studentData, "password123");
      students.push(created);
    }
    console.log(`Created ${students.length} students`);

    // Generate tuitions
    console.log("Generating tuitions...");
    const tuitions = [];
    for (const tutor of tutors) {
      const numTuitions = tutor.plan === "pro" ? randomInt(3, 8) : randomInt(1, 2);
      for (let i = 0; i < numTuitions; i++) {
        const tuition = generateTuition(tutor);
        const result = await tutionsCollection.insertOne(tuition);
        tuitions.push({ ...tuition, _id: result.insertedId });
      }
    }
    console.log(`Created ${tuitions.length} tuitions`);

    // Generate applications
    console.log("Generating applications...");
    const approvedTuitions = tuitions.filter(t => t.approvalStatus === "approved" && t.isActive);
    let applicationCount = 0;
    for (const student of students) {
      const numApplications = randomInt(0, 5);
      const shuffledTuitions = [...approvedTuitions].sort(() => Math.random() - 0.5);
      for (let i = 0; i < Math.min(numApplications, shuffledTuitions.length); i++) {
        const tuition = shuffledTuitions[i];
        const application = generateApplication(student, tuition);
        await applicationsCollection.insertOne(application);
        applicationCount++;
      }
    }
    console.log(`Created ${applicationCount} applications`);

    // Generate reviews (for accepted applications)
    console.log("Generating reviews...");
    const acceptedApplications = await applicationsCollection.find({ status: "accepted" }).toArray();
    let reviewCount = 0;
    for (const app of acceptedApplications) {
      const student = students.find(s => s.email === app.studentEmail);
      const tuition = tuitions.find(t => t._id.toString() === app.tuitionId);
      if (student && tuition && Math.random() < 0.7) { // 70% leave reviews
        const review = generateReview(student, tuition);
        await reviewsCollection.insertOne(review);
        reviewCount++;
      }
    }
    console.log(`Created ${reviewCount} reviews`);

    // Generate bookmarks
    console.log("Generating bookmarks...");
    let bookmarkCount = 0;
    for (const student of students) {
      const numBookmarks = randomInt(0, 8);
      const shuffledTuitions = [...approvedTuitions].sort(() => Math.random() - 0.5);
      for (let i = 0; i < Math.min(numBookmarks, shuffledTuitions.length); i++) {
        const tuition = shuffledTuitions[i];
        const bookmark = generateBookmark(student, tuition);
        await bookmarksCollection.insertOne(bookmark);
        bookmarkCount++;
      }
    }
    console.log(`Created ${bookmarkCount} bookmarks`);

    console.log("\n✅ Database seeded successfully!");
    console.log("Summary:");
    console.log(`  - 1 admin`);
    console.log(`  - ${tutors.length} tutors`);
    console.log(`  - ${students.length} students`);
    console.log(`  - ${tuitions.length} tuitions`);
    console.log(`  - ${applicationCount} applications`);
    console.log(`  - ${reviewCount} reviews`);
    console.log(`  - ${bookmarkCount} bookmarks`);

  } catch (err) {
    console.error("Error seeding database:", err);
  } finally {
    await client.close();
  }
}

// Run if executed directly
seedDatabase();