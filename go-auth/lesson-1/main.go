// Package main implements a complete authentication system from scratch using Go's standard library.
// This demonstrates how JWT tokens, refresh tokens, and cookie-based authentication work without external libraries.
package main

import (
	"crypto/hmac"        // For HMAC-SHA256 signature verification (constant-time comparison)
	"crypto/rand"        // For generating cryptographically secure random tokens
	"crypto/sha256"      // For SHA-256 hashing of refresh tokens
	"encoding/base64"    // For base64url encoding (JWT standard)
	"encoding/json"      // For JSON marshaling/unmarshaling
	"errors"             // For creating error messages
	"fmt"                // For string formatting
	"log"                // For logging server errors
	"net/http"           // For HTTP server functionality
	"strings"            // For string manipulation (splitting JWTs, trimming)
	"time"               // For token expiration timestamps

	"golang.org/x/crypto/bcrypt" // For secure password hashing (industry standard)
)

// User represents a user in our system.
// This is our in-memory user model (in production, this would be a database table).
type User struct {
	ID               string    // Unique user identifier (randomly generated)
	Email            string    // User's email address (used as login username)
	PasswordHash     []byte    // Bcrypt hash of the user's password (never store plaintext!)
	RefreshTokenHash []byte    // SHA-256 hash of the current refresh token (for security)
	RefreshTokenExp  time.Time // When the refresh token expires
}

// In-memory user storage (simulates a database).
// In production, replace these with actual database queries.
var usersByEmail = map[string]*User{} // Index by email for login lookups
var usersById = map[string]*User{}    // Index by ID for token validation

/*
Config: Application-wide authentication configuration.
These values control token lifetimes, JWT claims, and cookie settings.
*/
var (
	jwtIssuer    = "auth-from-scratch"                                                   // JWT "iss" claim - identifies who issued the token
	jwtAudience  = "web-client"                                                          // JWT "aud" claim - identifies intended recipient
	accessTTL    = 15 * time.Minute                                                      // Access token lifetime (short-lived for security)
	refreshTTL   = 7 * time.Hour                                                         // Refresh token lifetime (longer, stored in HttpOnly cookie)
	jwtSecret    = []byte("ff82f57da0f9df8f60a10a3fb29aca146bfedb88b967fd08c69ccb23c6ff44dc") // Secret key for HMAC-SHA256 signing (NEVER commit real secrets!)
	cookieName   = "rt"                                                                  // Name of the refresh token cookie
	cookieDomain = "localhost"                                                           // Cookie domain (set to your domain in production)
)

// withCORS is a middleware that enables Cross-Origin Resource Sharing (CORS).
// This allows your frontend (running on a different port) to make requests to this API.
// IMPORTANT: In production, be more restrictive with allowed origins!
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Get the Origin header from the request (where the request is coming from)
		origin := r.Header.Get("Origin")

		// Only allow requests from these specific origins (Vite and Create React App default ports)
		if origin == "http://localhost:5173" || origin == "http://localhost:3000" {
			w.Header().Set("Access-Control-Allow-Origin", origin)       // Echo back the origin (not "*" because we need credentials)
			w.Header().Set("Vary", "Origin")                            // Tell caches that response varies by Origin header
			w.Header().Set("Access-Control-Allow-Credentials", "true")  // Allow cookies to be sent cross-origin
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization") // Allow these headers
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE, PATCH") // Allow these HTTP methods
		}

		// Handle preflight requests (browsers send OPTIONS before actual request)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent) // 204 No Content - preflight approved
			return
		}

		// Pass the request to the next handler in the chain
		next.ServeHTTP(w, r)

	})
}

/*
JWT Implementation (HMAC-SHA256 / HS256)

This is a minimal JWT implementation using only the standard library.
JWT structure: header.payload.signature (all base64url encoded)

Standard JWT header for HS256: {"alg":"HS256","typ":"JWT"}
*/

// JWTClaims represents the payload of our JWT token.
// These are standard JWT claims (registered claims) defined in RFC 7519.
type JWTClaims struct {
	Sub string `json:"sub"` // Subject - who the token is about (user ID)
	Iss string `json:"iss"` // Issuer - who created the token (our service)
	Aud string `json:"aud"` // Audience - who should accept this token (our frontend)
	Exp int64  `json:"exp"` // Expiration time - Unix timestamp when token expires
	Iat int64  `json:"iat"` // Issued at - Unix timestamp when token was created
}

// base64Url encodes data using base64url encoding (JWT standard).
// Unlike standard base64, base64url:
// 1. Uses '-' instead of '+' and '_' instead of '/'
// 2. Removes padding ('=') to make it URL-safe without encoding
func base64Url(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// base64UrlDecode decodes a base64url encoded string.
// It adds back the padding that was removed during encoding.
func base64UrlDecode(s string) ([]byte, error) {
	// Add padding if necessary (base64 requires length to be multiple of 4)
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m) // Add 1-3 '=' characters as needed
	}

	return base64.URLEncoding.DecodeString(s)
}

// signJWT creates and signs a JWT token using HMAC-SHA256.
// JWT Format: base64url(header).base64url(payload).base64url(signature)
// Example: eyJhbGc...eyJzdWI...SflKxwRJSMeKKF2Q
func signJWT(claims JWTClaims, secret []byte) (string, error) {
	// Step 1: Create the header (always the same for HS256)
	header := `{"alg":"HS256","typ":"JWT"}`
	hEnc := base64Url([]byte(header))

	// Step 2: Convert claims to JSON and encode
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	pEnc := base64Url([]byte(payloadBytes))

	// Step 3: Combine header and payload (this is what we'll sign)
	unsigned := hEnc + "." + pEnc

	// Step 4: Calculate the HMAC-SHA256 signature
	// HMAC = Hash-based Message Authentication Code
	// It proves the token hasn't been tampered with and was created by us
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(unsigned))
	sig := mac.Sum(nil) // Get the signature bytes

	// Step 5: Encode the signature and create final token
	token := unsigned + "." + base64Url(sig)
	return token, nil
}

// parseAndVerifyJWT validates a JWT token and extracts the claims.
// This function performs THREE critical security checks:
// 1. Signature verification (proves token wasn't tampered with)
// 2. Expiration check (proves token is still valid)
// 3. Format validation (proves token is well-formed)
func parseAndVerifyJWT(token string, secret []byte) (JWTClaims, error) {

	var claims JWTClaims

	// Step 1: Split the token into its three parts
	parts := strings.Split(token, ".")

	if len(parts) != 3 {
		return claims, errors.New("invalid token format") // Must be header.payload.signature
	}

	// Step 2: Verify the signature (CRITICAL SECURITY CHECK)
	unsigned := parts[0] + "." + parts[1] // The part that was signed
	sigB, err := base64UrlDecode(parts[2]) // The signature we received

	if err != nil {
		return claims, errors.New("invalid signature encoding")
	}

	// Recalculate what the signature SHOULD be
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(unsigned))
	expected := mac.Sum(nil)

	// Use constant-time comparison to prevent timing attacks
	if !hmac.Equal(expected, sigB) {
		return claims, errors.New("signature mismatch") // Token was tampered with!
	}

	// Step 3: Decode and parse the payload
	payload, err := base64UrlDecode(parts[1])

	if err != nil {
		return claims, errors.New("invalid payload encoding")
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, errors.New("invalid claims")
	}

	// Step 4: Check if token has expired (CRITICAL SECURITY CHECK)
	now := time.Now().Unix()

	if claims.Exp <= now {
		return claims, errors.New("token expired") // Token is too old
	}

	return claims, nil
}

/*
Helper Functions
These utility functions simplify common operations throughout the application.
*/

// jsonResp sends a JSON response with the given status code.
// The 'v any' parameter can be any type that can be marshaled to JSON.
func jsonResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json") // Tell client we're sending JSON
	w.WriteHeader(status)                               // Set HTTP status code
	_ = json.NewEncoder(w).Encode(v)                    // Encode and send the response
}

// badReq sends a 400 Bad Request response with an error message.
func badReq(w http.ResponseWriter, msg string) {
	jsonResp(w, http.StatusBadRequest, map[string]string{"err": msg})
}

// unAuthorized sends a 401 Unauthorized response with an error message.
func unAuthorized(w http.ResponseWriter, msg string) {
	jsonResp(w, http.StatusUnauthorized, map[string]string{"err": msg})
}

// newID generates a random user ID using cryptographically secure random bytes.
// Returns a 16-byte random ID encoded as base64url (22 characters).
func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // Fill with random bytes
	return base64.RawURLEncoding.EncodeToString(b)
}

// newRefreshToken generates a new refresh token and its hash.
// Returns: (hash to store in DB, raw token to send to client)
//
// Security model:
// - We generate 32 random bytes (256 bits of entropy)
// - We hash it with SHA-256 and store the hash in the database
// - We send the raw token to the client in an HttpOnly cookie
// - When client sends it back, we hash it again and compare with stored hash
// This way, even if our database is compromised, attackers can't use the hashes as tokens.
func newRefreshToken() ([]byte, string) {

	raw := make([]byte, 32)
	_, _ = rand.Read(raw) // Generate 32 random bytes

	// Store hash on server (not the raw token!)
	h := sha256.Sum256(raw)

	// Return: (hash for DB, raw token for client)
	return h[:], base64.RawURLEncoding.EncodeToString(raw)

}

// hashRefresh takes a base64-encoded refresh token and returns its SHA-256 hash.
// This is used to compare incoming tokens with stored hashes.
func hashRefresh(rawBase64 string) []byte {
	raw, _ := base64.RawURLEncoding.DecodeString(rawBase64) // Decode from base64
	sum := sha256.Sum256(raw)                                // Hash it
	return sum[:]                                            // Convert array to slice
}

/*
HTTP Handlers
These functions handle incoming HTTP requests for authentication operations.
*/

// signUpReq represents the JSON body expected for signup requests.
type signUpReq struct {
	Email    string `json:"email"`    // User's email address
	Password string `json:"password"` // User's plaintext password (will be hashed)
}

// handleSignUp creates a new user account.
// POST /signup
// Body: {"email": "user@example.com", "password": "secretpassword"}
func handleSignUp(w http.ResponseWriter, r *http.Request) {

	var req signUpReq

	// Step 1: Parse the JSON request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badReq(w, "invalid json")
		return
	}

	// Step 2: Validate input
	if req.Email == "" || req.Password == "" {
		badReq(w, "email and password required")
		return
	}

	// Step 3: Check if email is already registered
	if _, ok := usersByEmail[req.Email]; ok {
		badReq(w, "email already registered")
		return
	}

	// Step 4: Hash the password using bcrypt
	// bcrypt is slow by design (makes brute-force attacks harder)
	// DefaultCost is currently 10 (2^10 = 1024 iterations)
	pwHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	if err != nil {
		jsonResp(w, 500, map[string]string{"error": "hashing failed"})
		return
	}

	// Step 5: Create the user
	u := &User{
		ID:           newID(),
		Email:        req.Email,
		PasswordHash: pwHash, // Store the hash, NEVER the plaintext password
	}

	// Step 6: Store in our "database" (in-memory maps)
	usersByEmail[u.Email] = u
	usersById[u.ID] = u

	// Step 7: Send success response
	jsonResp(w, http.StatusOK, map[string]any{
		"message": "user created",
		"userId":  u.ID,
	})

}

// handleLogin authenticates a user and issues tokens.
// POST /login
// Body: {"email": "user@example.com", "password": "secretpassword"}
//
// On success, returns:
// - Access token (JWT) in response body - short-lived, sent with each API request
// - Refresh token in HttpOnly cookie - long-lived, used to get new access tokens
func handleLogin(w http.ResponseWriter, r *http.Request) {

	var req signUpReq

	// Step 1: Parse request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badReq(w, "invalid json")
		return
	}

	// Step 2: Validate input
	if req.Email == "" || req.Password == "" {
		badReq(w, "email and password is required")
		return
	}

	// Step 3: Find user and verify password
	u, ok := usersByEmail[req.Email]

	// We use a single error message for both "user not found" and "wrong password"
	// to prevent attackers from enumerating valid email addresses
	if !ok || bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(req.Password)) != nil {
		unAuthorized(w, "invalid credentials")
		return
	}

	// Step 4: Issue Access Token (JWT)
	// Access tokens are short-lived and sent with every API request
	now := time.Now()
	claims := JWTClaims{
		Sub: u.ID,                      // Subject: user ID
		Iss: jwtIssuer,                 // Issuer: our service name
		Aud: jwtAudience,               // Audience: who can use this token
		Iat: now.Unix(),                // Issued at: current timestamp
		Exp: now.Add(accessTTL).Unix(), // Expiration: 15 minutes from now
	}

	access, _ := signJWT(claims, jwtSecret)

	// Step 5: Issue Refresh Token
	// Refresh tokens are long-lived and stored in HttpOnly cookies
	rtHash, rtRaw := newRefreshToken()
	u.RefreshTokenHash = rtHash               // Store hash in "database"
	u.RefreshTokenExp = now.Add(refreshTTL)   // Set expiration (7 hours)

	setRefreshCookie(w, rtRaw, u.RefreshTokenExp) // Send raw token to client

	// Step 6: Send response
	jsonResp(w, http.StatusOK, map[string]any{
		"accessToken": access,                       // Client stores this and sends it in Authorization header
		"expiredIn":   int(accessTTL.Seconds()),    // So client knows when to refresh (900 seconds = 15 min)
		"user":        map[string]string{"id": u.ID, "email": u.Email}, // User info for frontend
	})

}

// setRefreshCookie stores the refresh token in an HttpOnly cookie.
// HttpOnly cookies are MUCH more secure than localStorage for sensitive tokens:
// - Cannot be accessed by JavaScript (prevents XSS attacks)
// - Automatically sent with requests to same domain
// - Can be set to Secure (HTTPS only) in production
func setRefreshCookie(w http.ResponseWriter, rawBase64 string, exp time.Time) {

	c := &http.Cookie{
		Name:     cookieName,              // "rt" - the cookie name
		Value:    rawBase64,               // The base64-encoded refresh token
		Path:     "/",                     // Cookie is valid for all paths
		Expires:  exp,                     // When the cookie expires (7 hours)
		HttpOnly: true,                    // CRITICAL: Prevents JavaScript access (XSS protection)
		Secure:   false,                   // Set to true in production (HTTPS only)
		SameSite: http.SameSiteLaxMode,   // CSRF protection (blocks cross-site requests except GET)
		Domain:   cookieDomain,            // Set to your actual domain in production
	}

	http.SetCookie(w, c)

}

// clearRefreshCookie deletes the refresh token cookie (used during logout).
// We set the expiration to Unix epoch (Jan 1, 1970) which makes browsers delete it.
func clearRefreshCookie(w http.ResponseWriter) {

	c := &http.Cookie{
		Name:     cookieName,
		Value:    "",                 // Empty value
		Path:     "/",
		Expires:  time.Unix(0, 0),   // Set to past date to delete
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Domain:   cookieDomain,
	}

	http.SetCookie(w, c)

}

// handleRefresh issues a new access token using the refresh token.
// POST /refresh
//
// This endpoint is called when the access token expires (every 15 minutes).
// The client doesn't need to send anything - the refresh token is in the HttpOnly cookie.
//
// Security features:
// 1. Token rotation: Each refresh generates a NEW refresh token
// 2. One-time use: Old refresh token is invalidated immediately
// 3. Expiration check: Refresh tokens expire after 7 hours
func handleRefresh(w http.ResponseWriter, r *http.Request) {

	// Step 1: Get refresh token from cookie
	c, err := r.Cookie(cookieName)

	if err != nil || c.Value == "" {
		unAuthorized(w, "missing refresh cookie")
		return
	}

	// Step 2: Hash the incoming token
	rtHash := hashRefresh(c.Value)

	// Step 3: Find the user who owns this refresh token
	// We iterate through all users and use constant-time comparison for security
	var u *User

	for _, user := range usersById {
		if user.RefreshTokenHash != nil && hmac.Equal(user.RefreshTokenHash, rtHash) {
			u = user
			break
		}
	}

	if u == nil {
		unAuthorized(w, "invalid refresh token") // Token doesn't match any user
	}

	// Step 4: Check if refresh token has expired
	if time.Now().After(u.RefreshTokenExp) {
		unAuthorized(w, "refresh token expired")
		return
	}

	// Step 5: Rotate refresh token (issue a new one and invalidate the old)
	// This is a security best practice - limits the impact if a token is stolen
	newHash, newRaw := newRefreshToken()

	u.RefreshTokenHash = newHash                       // Update stored hash
	u.RefreshTokenExp = time.Now().Add(refreshTTL)    // Reset expiration
	setRefreshCookie(w, newRaw, u.RefreshTokenExp)    // Send new token to client

	// Step 6: Issue new access token
	now := time.Now()
	claims := JWTClaims{
		Sub: u.ID,                      // User ID
		Iss: u.Email,                   // Issuer (note: this should probably be jwtIssuer, not email - potential bug!)
		Aud: jwtAudience,               // Audience
		Iat: now.Unix(),                // Issued at
		Exp: now.Add(accessTTL).Unix(), // Expires in 15 minutes
	}

	access, _ := signJWT(claims, jwtSecret)

	// Step 7: Send new access token to client
	jsonResp(w, http.StatusOK, map[string]any{
		"accessToken": access,
		"exipresIn":   int(accessTTL.Seconds()), // Note: typo in "exipresIn" (should be "expiresIn")
	})

}

// handleLogout invalidates the refresh token and clears the cookie.
// POST /logout
//
// This endpoint:
// 1. Finds the user's refresh token in the database and deletes it
// 2. Clears the refresh token cookie
// 3. The access token will naturally expire (we can't invalidate it since it's stateless)
//
// Note: Since JWTs are stateless, the access token will remain valid until it expires.
// For true immediate logout, you'd need a token blacklist or short-lived tokens.
func handleLogout(w http.ResponseWriter, r *http.Request) {

	// Step 1: Get refresh token from cookie (if it exists)
	c, _ := r.Cookie(cookieName)

	// Step 2: If we have a refresh token, invalidate it in the database
	if c != nil && c.Value != "" {
		rtHash := hashRefresh(c.Value)

		// Find and clear the refresh token for this user
		for _, u := range usersById {
			if u.RefreshTokenHash != nil && hmac.Equal(u.RefreshTokenHash, rtHash) {
				u.RefreshTokenHash = nil    // Delete the token hash
				u.RefreshTokenExp = time.Time{} // Reset expiration to zero value
				break
			}
		}
	}

	// Step 3: Clear the cookie from the client's browser
	clearRefreshCookie(w)

	// Step 4: Confirm logout
	jsonResp(w, http.StatusOK, map[string]string{"message": "logged out"})

}

// authMiddleware is a middleware that protects routes requiring authentication.
// It extracts and validates the JWT from the Authorization header.
//
// Usage: mux.Handle("/protected", authMiddleware(http.HandlerFunc(myHandler)))
//
// Protected handlers can access the user ID via r.Header.Get("X-User-ID")
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Step 1: Get Authorization header
		// Expected format: "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
		h := r.Header.Get("Authorization")

		// Step 2: Check for Bearer token format
		if !strings.HasPrefix(h, "Bearer ") {
			unAuthorized(w, "missing bearer token")
			return
		}

		// Step 3: Extract the token (remove "Bearer " prefix)
		token := strings.TrimPrefix(h, "Bearer ")

		// Step 4: Verify the JWT signature and expiration
		claims, err := parseAndVerifyJWT(token, jwtSecret)

		if err != nil {
			unAuthorized(w, "invalid or expired token")
			return
		}

		// Step 5: Add user ID to request headers for downstream handlers
		// This allows protected endpoints to know WHO is making the request
		r.Header.Set("X-User-ID", claims.Sub)

		// Step 6: Continue to the protected handler
		next.ServeHTTP(w, r)

	})
}

// handleMe returns the current user's profile information.
// GET /me
// Requires: Authorization header with valid JWT
//
// This is a protected endpoint (wrapped with authMiddleware).
// It demonstrates how to access the authenticated user's information.
func handleMe(w http.ResponseWriter, r *http.Request) {

	// Step 1: Get user ID from header (set by authMiddleware)
	uid := r.Header.Get("X-User-ID")

	// Step 2: Look up user in our "database"
	u := usersById[uid]

	if u == nil {
		unAuthorized(w, "user not found") // User ID in token doesn't exist (shouldn't happen)
	}

	// Step 3: Return user information (but NOT sensitive data like password hash!)
	jsonResp(w, http.StatusOK, map[string]any{
		"id":    u.ID,
		"email": u.Email,
	})

}

// handleHealth is a simple health check endpoint.
// GET /health
// No authentication required - useful for monitoring/load balancers.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, http.StatusOK, map[string]string{"status": "ok"})
}

// main is the entry point of our application.
// It sets up routes and starts the HTTP server.
func main() {

	// Step 1: Create a new HTTP router (multiplexer)
	mux := http.NewServeMux()

	// Step 2: Register public routes (no authentication required)
	mux.HandleFunc("/health", handleHealth)   // Health check
	mux.HandleFunc("/signup", handleSignUp)   // User registration
	mux.HandleFunc("/login", handleLogin)     // User login (issues tokens)
	mux.HandleFunc("/refresh", handleRefresh) // Refresh access token
	mux.HandleFunc("/logout", handleLogout)   // Logout (invalidate refresh token)

	// Step 3: Register protected routes (authentication required)
	// Note: handleMe is wrapped with authMiddleware to protect it
	mux.Handle("/me", authMiddleware(http.HandlerFunc(handleMe))) // Get current user info

	// Step 4: Configure server address
	addr := ":8080"

	// Step 5: Start the server
	// The entire mux is wrapped with withCORS middleware to handle cross-origin requests
	fmt.Printf("Server started on %v\n", strings.TrimPrefix(addr, ":"))
	log.Fatal(http.ListenAndServe(addr, withCORS(mux)))

}

/*
AUTHENTICATION FLOW SUMMARY:

1. SIGNUP (/signup):
   User provides email + password → Password is hashed with bcrypt → User stored in DB

2. LOGIN (/login):
   User provides email + password → Password verified → Two tokens issued:
   - Access token (JWT): Short-lived (15 min), sent in response body
   - Refresh token: Long-lived (7 hours), sent as HttpOnly cookie

3. ACCESSING PROTECTED RESOURCES (/me):
   Client sends: Authorization: Bearer <access-token>
   → authMiddleware validates JWT → User ID extracted → Handler processes request

4. REFRESHING ACCESS TOKEN (/refresh):
   Client automatically sends refresh token cookie → Server validates it
   → Issues NEW access token + NEW refresh token (token rotation for security)

5. LOGOUT (/logout):
   Server invalidates refresh token in DB → Clears cookie
   → Access token naturally expires (can't be invalidated due to stateless nature)

KEY SECURITY FEATURES:
- Passwords: Bcrypt hashed (slow, salted, adaptive)
- Access tokens: Short-lived JWTs (limits damage if stolen)
- Refresh tokens: Long-lived, hashed in DB, HttpOnly cookies (XSS protection)
- Token rotation: New refresh token on each use (limits replay attacks)
- Constant-time comparisons: Prevents timing attacks
- CORS: Restricts which origins can access the API
- SameSite cookies: CSRF protection
*/
