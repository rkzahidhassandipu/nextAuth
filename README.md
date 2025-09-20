🚀 NextAuth + MongoDB Authentication Project

This project implements NextAuth.js with Credentials Provider, Google, and GitHub authentication, fully integrated with MongoDB as the database. It includes secure login, registration, session handling, and middleware-based route protection.

📂 Project Structure
```
/app
 ├── api
 │    └── auth
 │         └── [...nextauth]
 │              └── route.js      # NextAuth API route
 ├── action
 │    └── auth
 │         ├── loginUser.js       # Login logic
 │         └── register.js        # Registration logic
/layout.js                        # Layout wrapped with SessionProvider
/src
 ├── lib
 │    ├── authOptions.js          # NextAuth providers & config
 │    └── dbConnect.js            # MongoDB connection helper
 ├── provider
 │    └── NextAuthSessionProvider.js # SessionProvider wrapper
 └── middleware.js                # Route protection middleware

```
⚙️ Setup Instructions
## 1️⃣ Install Dependencies
```npm install next-auth mongodb bcrypt```

## 2️⃣ Configure Environment Variables

Create a .env.local file in the root directory:

```
NEXTAUTH_SECRET=your_nextauth_secret
NEXTAUTH_URL=http://localhost:3000
```
```
 DB_URI=mongodb+srv://<username>:<password>@cluster.mongodb.net/?retryWrites=true&w=majority
DB_NAME=your_db_name 
```

```
GITHUB_ID=your_github_client_id
GITHUB_SECRET=your_github_client_secret

GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

## 3️⃣ Authentication Setup
🔹 Website location: Getting started > guid > use the code

🔹 API Route: /app/api/auth/[...nextauth]/route.js
```
import NextAuth from "next-auth";
import { authOptions } from "@/lib/authOptions";

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
```



🔹Website location:Configuration > providers > credential

🔹 Providers Config: /src/lib/authOptions.js
```
import GitHubProvider from "next-auth/providers/github";
import CredentialsProvider from "next-auth/providers/credentials";
import { loginUser } from "@/app/action/auth/loginUser";
import GoogleProvider from "next-auth/providers/google";
import dbConnect, { collectionNamesOb } from "./dbConnect";


export const authOptions = {provider code here}

Provider ar CredentialsProvider vitore:  email: {label: ‘email’, type:’email’}

Authorize ar vitore:  const user = await loginUser(credentials);
        if (user) {
          return user;
        } else {
          return null;
        }
        ] ar pore
session: {
    strategy: "jwt",
  },
  secret: process.env.NEXTAUTH_SECRET,
```


🔹 Session Provider: /src/provider/NextAuthSessionProvider.js
```
"use client";

import { SessionProvider } from "next-auth/react";

const NextAuthSessionProvider = ({ children }) => {
  return <SessionProvider>{children}</SessionProvider>;
};

export default NextAuthSessionProvider;
```


Usage in layout.js:

```
import NextAuthSessionProvider from "@/provider/NextAuthSessionProvider";

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <NextAuthSessionProvider>
          {children}
        </NextAuthSessionProvider>
      </body>
    </html>
  );
}
```

4️⃣ Database Connection: /src/lib/dbConnect.js

🔹Website location: Go to MongoDB and click the connect button, then Driver, and copy the 3 lines
```
import { MongoClient, ServerApiVersion } from "mongodb";

const uri = process.env.DB_URI;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

export const collectionNamesOb = {
  usersCollection: "Users",
  servicesCollection: "Doctor_Services",
};

const dbConnect = (collectionName) => {
  return client.db(process.env.DB_NAME).collection(collectionName);
};

export default dbConnect;
```

5️⃣ Auth Actions
🔹 Login User: /app/action/auth/loginUser.js
```
'use server';

import bcrypt from "bcrypt";
import dbConnect, { collectionNamesOb } from "@/lib/dbConnect";

export const loginUser = async ({ email, password }) => {
  const userCollection = dbConnect(collectionNamesOb.usersCollection);
  const user = await userCollection.findOne({ email });

  if (!user) return null;

  const isPasswordOK = await bcrypt.compare(password, user.password);
  if (!isPasswordOK) return null;

  return user;
};
```
🔹 Register User: /app/action/auth/register.js
```
"use server";

import bcrypt from "bcrypt";
import dbConnect, { collectionNamesOb } from "@/lib/dbConnect";

export const registerUser = async (payload) => {
  const { email, password, confirmPassword } = payload;
  const userCollection = dbConnect(collectionNamesOb.usersCollection);

  const existingUser = await userCollection.findOne({ email });
  if (existingUser) return null;

  if (!email || !password) return null;

  const hashedPassword = await bcrypt.hash(password, 10);
  const hashedConfirmPassword = await bcrypt.hash(confirmPassword, 10);

  payload.password = hashedPassword;
  payload.confirmPassword = hashedConfirmPassword;

  const result = await userCollection.insertOne(payload);
  result.insertedId = result.insertedId.toString();

  return result;
};
```

6️⃣ Middleware Protection: /src/middleware.js
```
import { getToken } from "next-auth/jwt";
import { NextResponse } from "next/server";

export const middleware = async (req) => {
  const token = await getToken({
    req,
    secret: process.env.NEXTAUTH_SECRET,
    secureCookie: process.env.NODE_ENV === "production",
  });

  if (token) {
    return NextResponse.next();
  } else {
    return NextResponse.redirect(new URL("/login", req.url));
  }
};

export const config = {
  matcher: ["/my-bookings", "/my-bookings/:path*", "/checkout/:path*"],
};
```

📊 Example Data Fetch
const serviceCollection = dbConnect(collectionNamesOb.servicesCollection);
const data = await serviceCollection.find({}).toArray();

✅ Features

🔐 Authentication with NextAuth (Credentials, Google, GitHub)

📦 Secure login & registration using MongoDB

🔑 Passwords hashed with bcrypt

📄 Protected routes with Next.js middleware

🗂 Session management via SessionProvider

⚡ Server Actions for login/register
