import "dotenv/config";
import { MongoClient } from "mongodb";

const API = "http://localhost:3000";

async function main() {
  // Create admin via Better Auth sign-up
  const signUpRes = await fetch(`${API}/api/auth/sign-up/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: API },
    body: JSON.stringify({
      email: "admin@mentorlagbe.com",
      password: "password123",
      name: "Admin User",
    }),
  });
  const signUpData = await signUpRes.json();
  console.log("signUp:", signUpData.user ? "OK" : signUpData);

  // Update role/plan in DB
  const client = new MongoClient(process.env.MONGO_URI);
  await client.connect();
  const db = client.db("mentor_lagbe_db");
  await db.collection("user").updateOne(
    { email: "admin@mentorlagbe.com" },
    { $set: { role: "admin", plan: "pro", phone: "+880 1711111111", bio: "Platform administrator" } }
  );
  console.log("role updated to admin");

  // Test sign-in
  const signInRes = await fetch(`${API}/api/auth/sign-in/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: API },
    body: JSON.stringify({
      email: "admin@mentorlagbe.com",
      password: "password123",
    }),
  });
  const signInData = await signInRes.json();
  console.log("signIn:", signInData.user ? `OK role=${signInData.user.role}` : signInData);

  await client.close();
}

main().catch(console.error);