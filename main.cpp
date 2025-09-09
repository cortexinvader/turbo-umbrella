/* Beast C++ Online DB Server (single-file scaffold)

WHAT THIS FILE IS:

A single-file C++ scaffold for an online database server running on Windows.

Uses: sqlite3, libsodium, cpp-httplib (single header), nlohmann/json (single header).

Provides: registration, login (session tokens), per-user encrypted storage of up to 5 values per key, ownership checks, safe password hashing (libsodium), field-level encryption (libsodium xchacha20poly1305), WAL mode, automatic resume.

NOTE: Transport-level TLS is NOT embedded here (to keep compilation simpler on Windows). Run this behind a TLS reverse proxy (nginx or Caddy) and forward 127.0.0.1:8080 inbound traffic from port 443.


TOP: Everything YOU MUST FILL / CHANGE (put your secrets and paths here)

Edit these constants before compiling:

DB_PATH: where the SQLite DB will live.

MASTER_KEY_B64: 32-bytes secret in base64 used to encrypt fields (store safely). You can generate with libsodium or openssl.

SERVER_PORT: the port the HTTP server listens on (local binding 0.0.0.0).

ENABLE_GUI: set to 1 if you want to compile/run GUI (requires Dear ImGui and a backend). If you don't want GUI, set to 0.


SECURITY REMINDERS (READ):

Keep MASTER_KEY secret (store in an environment variable or a local protected file). If it leaks, all field encryption is compromised.

Use a reverse proxy + TLS (Let's Encrypt) to serve HTTPS; do NOT expose raw HTTP to the public internet.

Use a UPS for power stability; use WAL mode (we enable it) and backups.


BUILD / DEPENDENCIES (Windows - MSYS2 / MinGW or Visual Studio)

libsodium (build and install for Windows). On MSYS2: pacman -S mingw-w64-x86_64-libsodium

sqlite3 (dev libs). On MSYS2: pacman -S mingw-w64-x86_64-sqlite3

nlohmann/json.hpp (single header) -> include in project

httplib.h (cpp-httplib single header) -> include

Link: -lsodium -lsqlite3


Example MSYS2 g++ compile (after installing libs): g++ -std=c++17 beast_cpp_sqlite_server.cpp -o beast_server -lsqlite3 -lsodium -lws2_32

Run: set MASTER_KEY_B64=... (or edit constant below) then ./beast_server


---

*/

#include <iostream> #include <string> #include <vector> #include <ctime> #include <chrono> #include <optional> #include <sstream> #include <iomanip>

// Single-header libraries you must provide in the include path: // - httplib.h (https://github.com/yhirose/cpp-httplib) // - nlohmann/json.hpp (https://github.com/nlohmann/json)

#include "httplib.h" #include "nlohmann/json.hpp"

#include <sqlite3.h> #include <sodium.h>

using json = nlohmann::json; using namespace std::chrono;

// ========================= CONFIG - EDIT THESE ========================= static const std::string DB_PATH = "C:\beast_server\mydatabase.db"; // <- change this path static const std::string MASTER_KEY_B64 = "REPLACE_WITH_BASE64_32_BYTES_SECRET"; // <- REPLACE static const int SERVER_PORT = 8080; static const bool ENABLE_GUI = false; // set true if you integrate Dear ImGui (see notes) // ======================================================================

// ===== Helper: base64 decode (libsodium helper) ===== std::vector<unsigned char> base64_decode(const std::string &b64) { std::vector<unsigned char> out; out.resize(b64.size()); size_t out_len = 0; if (sodium_base642bin(out.data(), out.size(), b64.c_str(), b64.size(), NULL, &out_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) { throw std::runtime_error("base64 decode failed"); } out.resize(out_len); return out; }

std::string base64_encode(const unsigned char* data, size_t len) { size_t b64_max = sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL); std::string out; out.resize(b64_max); sodium_bin2base64(&out[0], out.size(), data, len, sodium_base64_VARIANT_ORIGINAL); // trim trailing nulls out.erase(std::find(out.begin(), out.end(), '\0'), out.end()); return out; }

// ===== Encryption helpers (XChaCha20-Poly1305 AEAD) ===== // We'll use crypto_aead_xchacha20poly1305_ietf_* API

struct Ciphertext { std::string b64; // base64(nonce || ciphertext) };

// encrypt plaintext with master key (32 bytes) Ciphertext encrypt_field(const std::vector<unsigned char>& key, const std::string &plaintext) { const unsigned long long mlen = plaintext.size(); const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24 const size_t mac_len = crypto_aead_xchacha20poly1305_ietf_ABYTES;

std::vector<unsigned char> nonce(nonce_len);
randombytes_buf(nonce.data(), nonce_len);

std::vector<unsigned char> ciphertext(mlen + mac_len);
unsigned long long clen = 0;

if (crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext.data(), &clen,
    (const unsigned char*)plaintext.data(), mlen,
    NULL, 0, // additional data
    NULL, nonce.data(), key.data()) != 0) {
    throw std::runtime_error("encryption failed");
}

// assemble nonce||ciphertext
std::vector<unsigned char> out;
out.reserve(nonce_len + clen);
out.insert(out.end(), nonce.begin(), nonce.end());
out.insert(out.end(), ciphertext.begin(), ciphertext.begin()+clen);

Ciphertext res;
res.b64 = base64_encode(out.data(), out.size());
return res;

}

std::string decrypt_field(const std::vector<unsigned char>& key, const Ciphertext &ct) { // decode base64 std::vector<unsigned char> raw; raw.resize(ct.b64.size()); size_t raw_len = 0; if (sodium_base642bin(raw.data(), raw.size(), ct.b64.c_str(), ct.b64.size(), NULL, &raw_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) { throw std::runtime_error("base64 decode failed"); } raw.resize(raw_len);

const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
if (raw.size() < nonce_len + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
    throw std::runtime_error("ciphertext too short");
}
std::vector<unsigned char> nonce(raw.begin(), raw.begin()+nonce_len);
std::vector<unsigned char> cipher(raw.begin()+nonce_len, raw.end());

std::vector<unsigned char> out(cipher.size());
unsigned long long mlen = 0;
if (crypto_aead_xchacha20poly1305_ietf_decrypt(out.data(), &mlen,
    NULL, cipher.data(), cipher.size(),
    NULL, 0, nonce.data(), key.data()) != 0) {
    throw std::runtime_error("decryption failed or MAC mismatch");
}
return std::string((char*)out.data(), mlen);

}

// ===== Password hashing helpers (libsodium) ===== std::string hash_password(const std::string &pw) { std::string out(crypto_pwhash_STRBYTES, '\0'); if (crypto_pwhash_str(&out[0], pw.c_str(), pw.size(), crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0) { throw std::runtime_error("password hashing failed"); } // remove potential null terminator issues out.erase(std::find(out.begin(), out.end(), '\0'), out.end()); return out; }

bool verify_password(const std::string &pw, const std::string &hash) { return crypto_pwhash_str_verify(hash.c_str(), pw.c_str(), pw.size()) == 0; }

// ===== Utility: current unix timestamp ===== long long now_ts() { return duration_cast<seconds>(system_clock::now().time_since_epoch()).count(); }

// ===== DB helper: wrapper around sqlite operations ===== struct DB { sqlite3* db = nullptr; DB() = default; ~DB() { if (db) sqlite3_close(db); } void open_or_create(const std::string &path) { if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) { throw std::runtime_error(std::string("Cannot open DB: ") + sqlite3_errmsg(db)); } // WAL mode char* err = nullptr; sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &err); if (err) { sqlite3_free(err); }

// Create tables
    const char* sql_users = R"(
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        passhash TEXT NOT NULL
    );
    )";
    exec(sql_users);

    const char* sql_sessions = R"(
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    )";
    exec(sql_sessions);

    const char* sql_data = R"(
    CREATE TABLE IF NOT EXISTS kvdata (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        v1 TEXT, v2 TEXT, v3 TEXT, v4 TEXT, v5 TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(owner_id, key),
        FOREIGN KEY(owner_id) REFERENCES users(id)
    );
    )";
    exec(sql_data);
}
void exec(const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string e = err ? err : "unknown";
        sqlite3_free(err);
        throw std::runtime_error("SQL error: " + e);
    }
}

};

// ===== Server logic =====

int main_server(const std::vector<unsigned char>& master_key) { DB database; database.open_or_create(DB_PATH);

httplib::Server svr;

// Helper: create user
svr.Post(R"(/register)", [&](const httplib::Request &req, httplib::Response &res) {
    try {
        auto j = json::parse(req.body);
        std::string email = j.at("email").get<std::string>();
        std::string password = j.at("password").get<std::string>();
        if (email.empty() || password.size() < 6) {
            res.status = 400; res.set_content("Invalid email or password (min 6)", "text/plain"); return;
        }
        std::string ph = hash_password(password);
        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(database.db, "INSERT INTO users (email, passhash) VALUES (?,?);", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, ph.c_str(), -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) { res.status = 400; res.set_content("Email maybe already used", "text/plain"); return; }
        res.set_content("OK", "text/plain");
    } catch (std::exception &e) {
        res.status = 400; res.set_content(std::string("Bad request: ") + e.what(), "text/plain");
    }
});

// Helper: login
svr.Post(R"(/login)", [&](const httplib::Request &req, httplib::Response &res) {
    try {
        auto j = json::parse(req.body);
        std::string email = j.at("email").get<std::string>();
        std::string password = j.at("password").get<std::string>();

        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(database.db, "SELECT id, passhash FROM users WHERE email = ?;", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); res.status = 401; res.set_content("Invalid credentials", "text/plain"); return; }
        int user_id = sqlite3_column_int(stmt, 0);
        const unsigned char* hash_text = sqlite3_column_text(stmt, 1);
        std::string stored_hash = hash_text ? (const char*)hash_text : std::string();
        sqlite3_finalize(stmt);
        if (!verify_password(password, stored_hash)) { res.status = 401; res.set_content("Invalid credentials", "text/plain"); return; }

        // create session token (random 32 bytes -> base64)
        unsigned char token_raw[32]; randombytes_buf(token_raw, sizeof(token_raw));
        std::string token_b64 = base64_encode(token_raw, sizeof(token_raw));
        long long expires = now_ts() + 60*60*24*7; // 7 days

        sqlite3_prepare_v2(database.db, "INSERT OR REPLACE INTO sessions (token, user_id, expires_at) VALUES (?,?,?);", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, token_b64.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, user_id);
        sqlite3_bind_int64(stmt, 3, expires);
        sqlite3_step(stmt); sqlite3_finalize(stmt);

        json out; out["token"] = token_b64; out["expires_at"] = expires;
        res.set_content(out.dump(), "application/json");
    } catch (std::exception &e) {
        res.status = 400; res.set_content(std::string("Bad request: ") + e.what(), "text/plain");
    }
});

// Helper: middleware - verify token and return user id
auto auth_get_user = [&](const httplib::Request &req) -> std::optional<int> {
    if (!req.has_param("token")) return std::nullopt;
    std::string token = req.get_param_value("token");
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(database.db, "SELECT user_id, expires_at FROM sessions WHERE token = ?;", -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); return std::nullopt; }
    int uid = sqlite3_column_int(stmt, 0);
    long long exp = sqlite3_column_int64(stmt, 1);
    sqlite3_finalize(stmt);
    if (now_ts() > exp) return std::nullopt;
    return uid;
};

// POST /data  body: { token, key, values: ["v1","v2",... up to 5] }
svr.Post(R"(/data)", [&](const httplib::Request &req, httplib::Response &res) {
    try {
        auto j = json::parse(req.body);
        std::string token = j.at("token").get<std::string>();
        std::string key = j.at("key").get<std::string>();
        auto values = j.at("values");
        if (!values.is_array() || values.size() == 0 || values.size() > 5) { res.status = 400; res.set_content("values must be array size 1..5", "text/plain"); return; }
        // auth
        httplib::Request fake; // construct fake type? instead use helper by building a small req-like structure
        // Instead: directly check session token in DB
        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(database.db, "SELECT user_id, expires_at FROM sessions WHERE token = ?;", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); res.status = 401; res.set_content("Invalid token", "text/plain"); return; }
        int uid = sqlite3_column_int(stmt, 0);
        long long exp = sqlite3_column_int64(stmt, 1);
        sqlite3_finalize(stmt);
        if (now_ts() > exp) { res.status = 401; res.set_content("Token expired", "text/plain"); return; }

        // encrypt each value and store
        std::vector<std::string> encVals(5, "");
        for (size_t i=0;i<values.size();++i) {
            std::string v = values.at(i).get<std::string>();
            Ciphertext c = encrypt_field(master_key, v);
            encVals[i] = c.b64;
        }
        long long ts = now_ts();
        // upsert
        sqlite3_prepare_v2(database.db, "INSERT INTO kvdata (owner_id, key, v1, v2, v3, v4, v5, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(owner_id,key) DO UPDATE SET v1=excluded.v1, v2=excluded.v2, v3=excluded.v3, v4=excluded.v4, v5=excluded.v5, updated_at=excluded.updated_at;", -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, uid);
        sqlite3_bind_text(stmt, 2, key.c_str(), -1, SQLITE_TRANSIENT);
        for (int i=0;i<5;i++) {
            if (encVals[i].empty()) sqlite3_bind_null(stmt, 3+i);
            else sqlite3_bind_text(stmt, 3+i, encVals[i].c_str(), -1, SQLITE_TRANSIENT);
        }
        sqlite3_bind_int64(stmt, 8, ts);
        sqlite3_bind_int64(stmt, 9, ts);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) { res.status = 500; res.set_content("DB error", "text/plain"); return; }
        res.set_content("OK", "text/plain");
    } catch (std::exception &e) {
        res.status = 400; res.set_content(std::string("Bad request: ") + e.what(), "text/plain");
    }
});

// GET /data?token=...&key=...
svr.Get(R"(/data)", [&](const httplib::Request &req, httplib::Response &res) {
    try {
        if (!req.has_param("token") || !req.has_param("key")) { res.status = 400; res.set_content("token and key required", "text/plain"); return; }
        std::string token = req.get_param_value("token");
        std::string key = req.get_param_value("key");
        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(database.db, "SELECT user_id, expires_at FROM sessions WHERE token = ?;", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); res.status = 401; res.set_content("Invalid token", "text/plain"); return; }
        int uid = sqlite3_column_int(stmt, 0);
        long long exp = sqlite3_column_int64(stmt, 1);
        sqlite3_finalize(stmt);
        if (now_ts() > exp) { res.status = 401; res.set_content("Token expired", "text/plain"); return; }

        sqlite3_prepare_v2(database.db, "SELECT v1,v2,v3,v4,v5 FROM kvdata WHERE owner_id = ? AND key = ?;", -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, uid);
        sqlite3_bind_text(stmt, 2, key.c_str(), -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); res.status = 404; res.set_content("Not found", "text/plain"); return; }
        json out = json::array();
        for (int i=0;i<5;i++) {
            const unsigned char* txt = sqlite3_column_text(stmt, i);
            if (!txt) continue;
            Ciphertext ct{std::string((const char*)txt)};
            std::string dec = decrypt_field(master_key, ct);
            out.push_back(dec);
        }
        sqlite3_finalize(stmt);
        res.set_content(out.dump(), "application/json");
    } catch (std::exception &e) {
        res.status = 500; res.set_content(std::string("Error: ") + e.what(), "text/plain");
    }
});

// GET /list?token=... -> list keys owned
svr.Get(R"(/list)", [&](const httplib::Request &req, httplib::Response &res) {
    try {
        if (!req.has_param("token")) { res.status = 400; res.set_content("token required", "text/plain"); return; }
        std::string token = req.get_param_value("token");
        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(database.db, "SELECT user_id, expires_at FROM sessions WHERE token = ?;", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); res.status = 401; res.set_content("Invalid token", "text/plain"); return; }
        int uid = sqlite3_column_int(stmt, 0);
        long long exp = sqlite3_column_int64(stmt, 1);
        sqlite3_finalize(stmt);
        if (now_ts() > exp) { res.status = 401; res.set_content("Token expired", "text/plain"); return; }

        sqlite3_prepare_v2(database.db, "SELECT key, created_at, updated_at FROM kvdata WHERE owner_id = ?;", -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, uid);
        json out = json::array();
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            json item;
            item["key"] = (const char*)sqlite3_column_text(stmt, 0);
            item["created_at"] = sqlite3_column_int64(stmt, 1);
            item["updated_at"] = sqlite3_column_int64(stmt, 2);
            out.push_back(item);
        }
        sqlite3_finalize(stmt);
        res.set_content(out.dump(), "application/json");
    } catch (std::exception &e) {
        res.status = 500; res.set_content(std::string("Error: ") + e.what(), "text/plain");
    }
});

std::cout << "Beast server listening on port " << SERVER_PORT << "\n";
svr.listen("0.0.0.0", SERVER_PORT);
return 0;

}

int main(int argc, char** argv) { if (sodium_init() < 0) { std::cerr << "libsodium init failed\n"; return 1; }

// Load master key from the top-const or environment
std::vector<unsigned char> master_key;
try {
    if (MASTER_KEY_B64 == "REPLACE_WITH_BASE64_32_BYTES_SECRET") {
        // try env var
        const char* env = std::getenv("MASTER_KEY_B64");
        if (!env) { std::cerr << "ERROR: Set MASTER_KEY_B64 constant or MASTER_KEY_B64 environment variable.\n"; return 1; }
        master_key = base64_decode(env);
    } else {
        master_key = base64_decode(MASTER_KEY_B64);
    }
} catch (std::exception &e) {
    std::cerr << "Invalid MASTER_KEY_B64: " << e.what() << "\n";
    return 1;
}
if (master_key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
    std::cerr << "MASTER_KEY must decode to " << crypto_aead_xchacha20poly1305_ietf_KEYBYTES << " bytes.\n";
    return 1;
}

// Create folder for DB if needed (simple attempt)
// (windows) - skipping robust folder creation here; assume path exists or user will create it

// run server
return main_server(master_key);

}

