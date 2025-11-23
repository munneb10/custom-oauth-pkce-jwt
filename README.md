# 🚀 OAuth 2.0 + PKCE + JWT From Scratch

*A tiny project that explains one of the most misunderstood flows in the industry.*

---

## 🧠 Why I Built This

We have always used “Login with Google”, “Login with GitHub”, “Sign in with Facebook”…
But mostly 🤨 never really understood **what happens behind the scenes**.

Then one day it hit me:

> “Why not build the entire OAuth 2.0 flow myself?
> No Google. No Auth0. No Keycloak.
> Just me… and pure code.”

So this project was born.

It is a **fully custom implementation of OAuth 2.0 Authorization Code Flow with PKCE + JWT**
the same flow used by real apps like mobile clients, SPAs, and modern cloud apps.

And the best part?

It fits in your head.

---

# What This Project Demonstrates

This mini-project covers real software engineering concepts used by giants like Spotify, Google, AWS, Netflix:

### **✔ OAuth 2.0 Authorization Code Flow**

The most secure login flow for user-based authentication.

### **✔ PKCE (Proof Key for Code Exchange)**

A crucial security layer for public clients (SPAs, mobile apps).
No client secret needed — PKCE protects you.

### **✔ JWT Access & Refresh Tokens**

Stateless authentication, token expiration, and token rotation.

### **✔ Microservice Architecture**

Three independent services:

* **Auth Server** → handles login + tokens
* **Resource Server** → protects APIs
* **Client App** → simulates a browser/mobile client

### **✔ Redirect-based Authentication**

The magic behind *“Sign in with X”* UX.

### **✔ Token Refresh Cycle**

Silent re-authentication using refresh tokens.

This is one of those projects that looks small but teaches very big things.

---

# 🔐 The Full Flow in 9 Steps

### **1. Client generates PKCE (code_verifier & code_challenge)**

Makes the flow secure even without client secrets.

### **2. Client redirects user → `/authorize`**

User is taken to the Auth Server login page.

### **3. User logs in**

Auth Server checks credentials.

### **4. Auth Server issues Authorization Code**

(One-time use, expires in minutes)

### **5. Client exchanges code + code_verifier → `/token`**

Auth Server validates PKCE.

### **6. Auth Server issues tokens**

* `access_token` (JWT, 5 min)
* `refresh_token` (JWT, 7 days)

### **7. Client calls protected API** (Resource Server)

Sends:

```
Authorization: Bearer <access_token>
```

### **8. API verifies JWT**

If valid → returns protected data.

### **9. If token expires client uses refresh token**

No need to log in again.

This is the same system behind every major modern login flow.

---

# 📁 Project Structure

```
oauth-pkce-jwt-demo/
├── auth-server/        # Issues auth codes + tokens, handles PKCE
├── resource-server/    # Protected API that validates JWTs
└── client-app/         # Simple SPA implementing PKCE + code flow
```

---

# 🛠️ Running the Project Locally

## 1. Start the Auth Server

```
cd auth-server
npm install
npm run dev
```

Runs at:
👉 [http://localhost:4000](http://localhost:4000)

---

## 2. Start the Resource Server

```
cd ../resource-server
npm install
npm run dev
```

Runs at:
👉 [http://localhost:5000](http://localhost:5000)

---

## 3. Start the Client App

```
cd ../client-app
npx serve -l 3000
```

Open:
👉 [http://localhost:3000](http://localhost:3000)

---

# 🕹️ Try the Flow Yourself

1. Open **[http://localhost:3000](http://localhost:3000)**
2. Click **“Login with Demo Auth”**
3. Login using:

   * username: `muneeb`
   * password: `password123`
4. Watch the browser show:

   * PKCE values
   * Authorization code
   * Access token (JWT)
   * Refresh token
5. Click **“Call Protected API”**

   * You’ll get a secured profile response
6. Click **“Refresh Access Token”**

   * Silent token refresh flow happens

You’ve officially built the same mechanism behind:
**Spotify Login, Google OAuth, GitHub OAuth, Auth0, AWS Cognito**.

---

# 🌟 Why This Project Matters

Most developers only use OAuth libraries.
Very few actually know **how OAuth works internally**.

This project shows:

* You understand system design
* You understand auth architecture
* You can build distributed flows
* You grasp modern security patterns
* You can reason about tokens and lifecycles
* You can explain redirect-based authentication

This is **interview-level mastery**.

---

# 🚀 Future Improvements (If You Want to Expand)

* Add scopes & consent screen
* Add database for tokens & users
* Implement logout + token revocation
* Add support for RS256 (public/private key JWTs)
* Add multi-client registration
* Support PKCE for native mobile apps

---

# 🏁 Final Words

I created this project because I believe:

**You don’t truly understand security
until you build the system yourself.**

This repo is my tiny attempt at demystifying OAuth
by removing the magic and showing the code behind it.

If this helped you, feel free to ⭐ the repo
and share your thoughts with me!
