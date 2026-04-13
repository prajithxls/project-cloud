// ── Cognito Auth Service (no SDK — pure fetch, zero dependencies) ─────────────

const REGION        = "ap-south-1";
const USER_POOL_ID  = "ap-south-1_mFXWRsnQQ";
const CLIENT_ID     = "19do3v8880gde88n4babe03gi2";
const ENDPOINT      = `https://cognito-idp.${REGION}.amazonaws.com/`;

// ── helpers ───────────────────────────────────────────────────────────────────
function cognitoRequest(target, body) {
  return fetch(ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": target,
    },
    body: JSON.stringify(body),
  }).then(async (res) => {
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || data.__type || "Unknown error");
    return data;
  });
}

// ── Sign Up ───────────────────────────────────────────────────────────────────
export async function signUp(email, password) {
  return cognitoRequest("AWSCognitoIdentityProviderService.SignUp", {
    ClientId: CLIENT_ID,
    Username: email,
    Password: password,
    UserAttributes: [{ Name: "email", Value: email }],
  });
}

// ── Confirm Sign Up ───────────────────────────────────────────────────────────
export async function confirmSignUp(email, code) {
  return cognitoRequest("AWSCognitoIdentityProviderService.ConfirmSignUp", {
    ClientId: CLIENT_ID,
    Username: email,
    ConfirmationCode: code,
  });
}

// ── Resend Confirmation Code ──────────────────────────────────────────────────
export async function resendCode(email) {
  return cognitoRequest("AWSCognitoIdentityProviderService.ResendConfirmationCode", {
    ClientId: CLIENT_ID,
    Username: email,
  });
}

// ── Sign In ───────────────────────────────────────────────────────────────────
export async function signIn(email, password) {
  const data = await cognitoRequest("AWSCognitoIdentityProviderService.InitiateAuth", {
    AuthFlow: "USER_PASSWORD_AUTH",
    ClientId: CLIENT_ID,
    AuthParameters: { USERNAME: email, PASSWORD: password },
  });
  const tokens = data.AuthenticationResult;
  localStorage.setItem("csc_id_token",      tokens.IdToken);
  localStorage.setItem("csc_access_token",  tokens.AccessToken);
  localStorage.setItem("csc_refresh_token", tokens.RefreshToken);
  localStorage.setItem("csc_email",         email);

  // Extract Cognito sub (unique user ID) from ID token
  try {
    const payload = JSON.parse(atob(tokens.IdToken.split(".")[1]));
    const userId  = payload.sub; // UUID — unique per user, never changes
    localStorage.setItem("csc_user_id", userId);
  } catch {}

  return tokens;
}

// ── Sign Out ──────────────────────────────────────────────────────────────────
export function signOut() {
  localStorage.removeItem("csc_id_token");
  localStorage.removeItem("csc_access_token");
  localStorage.removeItem("csc_refresh_token");
  localStorage.removeItem("csc_email");
  localStorage.removeItem("csc_user_id");
}

// ── Get current user ──────────────────────────────────────────────────────────
export function getCurrentUser() {
  const token = localStorage.getItem("csc_id_token");
  const email = localStorage.getItem("csc_email");
  if (!token) return null;
  // Check expiry
  try {
    const payload = JSON.parse(atob(token.split(".")[1]));
    if (payload.exp * 1000 < Date.now()) { signOut(); return null; }
    const userId = localStorage.getItem("csc_user_id");
    return { email, token, userId };
  } catch {
    return null;
  }
}

// ── Get unique user ID (Cognito sub) ─────────────────────────────────────────
export function getUserId() {
  return localStorage.getItem("csc_user_id") || null;
}

// ── Forgot Password ───────────────────────────────────────────────────────────
export async function forgotPassword(email) {
  return cognitoRequest("AWSCognitoIdentityProviderService.ForgotPassword", {
    ClientId: CLIENT_ID,
    Username: email,
  });
}

// ── Confirm Forgot Password ───────────────────────────────────────────────────
export async function confirmForgotPassword(email, code, newPassword) {
  return cognitoRequest("AWSCognitoIdentityProviderService.ConfirmForgotPassword", {
    ClientId: CLIENT_ID,
    Username: email,
    ConfirmationCode: code,
    Password: newPassword,
  });
}