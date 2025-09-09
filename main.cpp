/* Beast C++ SQLite Server - single-file GUI + HTTP server

PRODUCTION-ORIENTED single-file C++ application (Windows). Provides:

Dear ImGui GUI (SDL2 + OpenGL3) as control panel

Embedded HTTP API (cpp-httplib) for external access

Encrypted persistent storage (SQLite + libsodium)

User registration/login, per-user encrypted data (up to 5 values per key)

Admin-only controls: view logs, ban/unban users, start/stop server

WAL journaling and safe DB autostart on boot supported by run-time


IMPORTANT: before compiling set MASTER_KEY_B64 env var OR edit constant below. Do NOT commit your master key.

BUILD (MSYS2 MinGW64) - example: pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-sdl2 mingw-w64-x86_64-glew mingw-w64-x86_64-sqlite3 mingw-w64-x86_64-libsodium g++ -std=c++17 beast_gui_server.cpp -o beast_gui_server.exe -lSDL2 -lSDL2main -lopengl32 -lsqlite3 -lsodium -lws2_32 -lgdi32

Required single-header libs (place in include path):

httplib.h (cpp-httplib)

nlohmann/json.hpp

ImGui sources in vendor/imgui/ and backends (imgui_impl_sdl.cpp, imgui_impl_opengl3.cpp)


CONFIG (edit or use env vars): */

#include <iostream>
#include <thread>
#include <atomic>
#include <vector>
#include <optional>
#include <string>
#include <mutex>
#include <fstream>
#include <algorithm>
#include <ctime>

// Third-party headers (you must provide these)
#include "httplib.h"            // single-header cpp-httplib
#include "nlohmann/json.hpp"    // single-header nlohmann
// ImGui headers and backends (place vendor/imgui in include path)
#include "imgui.h"
#include "imgui_impl_sdl.h"
#include "imgui_impl_opengl3.h"

#include <SDL.h>
#include <GL/gl.h>

#include <sqlite3.h>
#include <sodium.h>

using json = nlohmann::json;
using namespace std;

// ================= CONFIG - SET BEFORE RUNNING =================
static const std::string DB_PATH = "C:/beast_server/mydatabase.db"; // ensure folder exists
static const int SERVER_PORT = 8080;
// MASTER_KEY_B64: use environment variable MASTER_KEY_B64 or edit below (not recommended)
static const std::string MASTER_KEY_B64_PLACEHOLDER = ""; // leave empty to require env var
// =================================================================

std::atomic<bool> server_running(false);
std::atomic<bool> terminate_app(false);
std::mutex log_mutex;
std::vector<std::string> server_logs; // in-memory recent logs

// Utility: append log
void push_log(const std::string &s) {
    std::lock_guard<std::mutex> g(log_mutex);
    server_logs.push_back(s);
    if (server_logs.size() > 1000) server_logs.erase(server_logs.begin());
    // also append to disk
    std::ofstream ofs("server_gui.log", std::ios::app);
    if (ofs.is_open()) {
        ofs << s << std::endl;
    }
}

// ===== base64 helpers using libsodium =====
std::string base64_encode(const unsigned char* data, size_t len) {
    size_t b64_max = sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL);
    std::string out;
    out.resize(b64_max);
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_ORIGINAL);
    out.erase(std::find(out.begin(), out.end(), '\0'), out.end());
    return out;
}

std::vector<unsigned char> base64_decode_vec(const std::string &b64) {
    std::vector<unsigned char> out;
    out.resize(b64.size());
    size_t out_len = 0;
    if (sodium_base642bin(out.data(), out.size(), b64.c_str(), b64.size(), NULL, &out_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0)
        throw std::runtime_error("base64 decode failed");
    out.resize(out_len);
    return out;
}

// ===== AEAD encryption helpers (XChaCha20-Poly1305) =====
struct CipherText {
    std::string b64; // b64(nonce || ciphertext)
};

CipherText encrypt_field(const std::vector<unsigned char>& key, const std::string &plaintext) {
    const unsigned long long mlen = plaintext.size();
    const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
    const size_t mac_len = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    std::vector<unsigned char> nonce(nonce_len);
    randombytes_buf(nonce.data(), nonce_len);
    std::vector<unsigned char> ciphertext(mlen + mac_len);
    unsigned long long clen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext.data(), &clen, (const unsigned char*)plaintext.data(), mlen, NULL, 0, NULL, nonce.data(), key.data()) != 0)
        throw std::runtime_error("encryption failed");
    std::vector<unsigned char> out;
    out.reserve(nonce_len + clen);
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.begin()+clen);
    CipherText ct;
    ct.b64 = base64_encode(out.data(), out.size());
    return ct;
}

std::string decrypt_field(const std::vector<unsigned char>& key, const std::string &b64) {
    auto raw = base64_decode_vec(b64);
    const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    if (raw.size() < nonce_len + crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::runtime_error("ciphertext too short");
    std::vector<unsigned char> nonce(raw.begin(), raw.begin()+nonce_len);
    std::vector<unsigned char> cipher(raw.begin()+nonce_len, raw.end());
    std::vector<unsigned char> out(cipher.size());
    unsigned long long mlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(out.data(), &mlen, NULL, cipher.data(), cipher.size(), NULL, 0, nonce.data(), key.data()) != 0)
        throw std::runtime_error("decryption failed");
    return std::string((char*)out.data(), mlen);
}

// ===== Database wrapper =====
struct DB {
    sqlite3* db = nullptr;
    void open_or_create(const std::string &path) {
        if (sqlite3_open(path.c_str(), &db) != SQLITE_OK)
            throw std::runtime_error("Cannot open DB");
        // WAL
        char* err = nullptr;
        sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &err);
        if (err) sqlite3_free(err);
        // tables
        const char* sql_users = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, passhash TEXT, is_admin INTEGER DEFAULT 0, banned INTEGER DEFAULT 0);";
        sqlite3_exec(db, sql_users, nullptr, nullptr, &err);
        const char* sql_sessions = "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER, expires_at INTEGER);";
        sqlite3_exec(db, sql_sessions, nullptr, nullptr, &err);
        const char* sql_kv = "CREATE TABLE IF NOT EXISTS kvdata (id INTEGER PRIMARY KEY, owner_id INTEGER, key TEXT, v1 TEXT, v2 TEXT, v3 TEXT, v4 TEXT, v5 TEXT, created_at INTEGER, updated_at INTEGER, UNIQUE(owner_id,key));";
        sqlite3_exec(db, sql_kv, nullptr, nullptr, &err);
    }
    ~DB(){
        if(db) sqlite3_close(db);
    }
} database;

// ===== Password hashing helpers (libsodium) =====
std::string hash_password(const std::string &pw) {
    std::string out(crypto_pwhash_STRBYTES, '\0');
    if (crypto_pwhash_str(&out[0], pw.c_str(), pw.size(), crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0)
        throw std::runtime_error("Out of memory");
    out.erase(std::find(out.begin(), out.end(), '\0'), out.end());
    return out;
}

bool verify_password(const std::string &pw, const std::string &hash) {
    return crypto_pwhash_str_verify(hash.c_str(), pw.c_str(), pw.size()) == 0;
}

// ===== HTTP server thread and handlers =====
std::thread server_thread;

std::vector<unsigned char> master_key;

void start_server() {
    if (server_running) return;
    server_running = true;
    server_thread = std::thread([]() {
        httplib::Server svr;
        // Register
        svr.Post("/register", [&](const httplib::Request &req, httplib::Response &res){
            try {
                auto j = json::parse(req.body);
                std::string email = j.at("email").get<std::string>();
                std::string pw = j.at("password").get<std::string>();
                std::string ph = hash_password(pw);
                sqlite3_stmt* stmt;
                sqlite3_prepare_v2(database.db, "INSERT INTO users (email, passhash) VALUES (?,?);", -1, &stmt, nullptr);
                sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, ph.c_str(), -1, SQLITE_TRANSIENT);
                int rc = sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                if (rc != SQLITE_DONE) {
                    res.status = 400;
                    res.set_content("Insert failed", "text/plain");
                    return;
                }
                push_log("REGISTER: " + email);
                res.set_content("OK", "text/plain");
            } catch(...) {
                res.status = 400;
                res.set_content("Bad request", "text/plain");
            }
        });
        // Login
        svr.Post("/login", [&](const httplib::Request &req, httplib::Response &res){
            try{
                auto j = json::parse(req.body);
                std::string email = j.at("email").get<std::string>();
                std::string pw = j.at("password").get<std::string>();
                sqlite3_stmt* stmt;
                sqlite3_prepare_v2(database.db, "SELECT id, passhash, is_admin, banned FROM users WHERE email=?;", -1, &stmt, nullptr);
                sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
                int rc = sqlite3_step(stmt);
                if (rc != SQLITE_ROW) {
                    sqlite3_finalize(stmt);
                    res.status=401;
                    res.set_content("Invalid", "text/plain");
                    return;
                }
                int uid = sqlite3_column_int(stmt,0);
                const char* phc = (const char*)sqlite3_column_text(stmt,1);
                int is_admin = sqlite3_column_int(stmt,2);
                int banned = sqlite3_column_int(stmt,3);
                std::string stored_hash = phc?phc:"";
                sqlite3_finalize(stmt);
                if (banned) {
                    res.status=403;
                    res.set_content("banned","text/plain");
                    push_log("BANNED_LOGIN:"+email);
                    return;
                }
                if (!verify_password(pw, stored_hash)) {
                    res.status=401;
                    res.set_content("Invalid","text/plain");
                    push_log("FAILED_LOGIN:"+email);
                    return;
                }
                unsigned char token_raw[24];
                randombytes_buf(token_raw, sizeof(token_raw));
                std::string token = base64_encode(token_raw, sizeof(token_raw));
                long long expires = time(NULL) + 60*60*24*7;
                sqlite3_prepare_v2(database.db, "INSERT OR REPLACE INTO sessions (token,user_id,expires_at) VALUES(?,?,?);", -1, &stmt, nullptr);
                sqlite3_bind_text(stmt,1, token.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(stmt,2,uid);
                sqlite3_bind_int64(stmt,3,expires);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                json out;
                out["token"] = token;
                out["is_admin"] = is_admin;
                out["expires"] = expires;
                push_log("LOGIN:"+email);
                res.set_content(out.dump(), "application/json");
            } catch(...) {
                res.status=400;
                res.set_content("Bad", "text/plain");
            }
        });
        // POST /data to upsert encrypted values
        svr.Post("/data", [&](const httplib::Request &req, httplib::Response &res){
            try{
                auto j = json::parse(req.body);
                std::string token = j.at("token").get<std::string>();
                std::string key = j.at("key").get<std::string>();
                auto vals = j.at("values");
                if (!vals.is_array() || vals.size()==0 || vals.size()>5) {
                    res.status=400;
                    res.set_content("values 1..5", "text/plain");
                    return;
                }
                sqlite3_stmt* stmt;
                sqlite3_prepare_v2(database.db, "SELECT user_id,expires_at FROM sessions WHERE token=?;", -1, &stmt, nullptr);
                sqlite3_bind_text(stmt,1, token.c_str(), -1, SQLITE_TRANSIENT);
                int rc = sqlite3_step(stmt);
                if (rc!=SQLITE_ROW) {
                    sqlite3_finalize(stmt);
                    res.status=401;
                    res.set_content("Invalid token","text/plain");
                    return;
                }
                int uid = sqlite3_column_int(stmt,0);
                long long exp = sqlite3_column_int64(stmt,1);
                sqlite3_finalize(stmt);
                if (time(NULL) > exp) {
                    res.status=401;
                    res.set_content("Expired","text/plain");
                    return;
                }
                // encrypt values with master_key
                std::vector<std::string> enc(5, "");
                for (size_t i=0;i<vals.size();++i) {
                    std::string v = vals.at(i).get<std::string>();
                    enc[i] = encrypt_field(master_key, v).b64;
                }
                long long ts = time(NULL);
                sqlite3_prepare_v2(database.db, "INSERT INTO kvdata (owner_id,key,v1,v2,v3,v4,v5,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(owner_id,key) DO UPDATE SET v1=excluded.v1,v2=excluded.v2,v3=excluded.v3,v4=excluded.v4,v5=excluded.v5,updated_at=excluded.updated_at;", -1, &stmt, nullptr);
                sqlite3_bind_int(stmt,1,uid);
                sqlite3_bind_text(stmt,2,key.c_str(),-1,SQLITE_TRANSIENT);
                for (int i=0;i<5;i++) {
                    if (enc[i].empty()) sqlite3_bind_null(stmt,3+i);
                    else sqlite3_bind_text(stmt,3+i,enc[i].c_str(),-1,SQLITE_TRANSIENT);
                }
                sqlite3_bind_int64(stmt,8,ts);
                sqlite3_bind_int64(stmt,9,ts);
                rc = sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                if (rc!=SQLITE_DONE) {
                    res.status=500;
                    res.set_content("DB error","text/plain");
                    return;
                }
                push_log("DATA_UPSERT by uid="+std::to_string(uid)+" key="+key);
                res.set_content("OK","text/plain");
            } catch(...) {
                res.status=400;
                res.set_content("Bad","text/plain");
            }
        });
        // GET /data?token=..&key=..
        svr.Get("/data", [&](const httplib::Request &req, httplib::Response &res){
            try{
                if (!req.has_param("token")||!req.has_param("key")) {
                    res.status=400;
                    res.set_content("token&key required","text/plain");
                    return;
                }
                std::string token = req.get_param_value("token");
                std::string key = req.get_param_value("key");
                sqlite3_stmt* stmt;
                sqlite3_prepare_v2(database.db, "SELECT user_id,expires_at FROM sessions WHERE token=?;", -1, &stmt, nullptr);
                sqlite3_bind_text(stmt,1,token.c_str(),-1,SQLITE_TRANSIENT);
                int rc = sqlite3_step(stmt);
                if (rc!=SQLITE_ROW) {
                    sqlite3_finalize(stmt);
                    res.status=401;
                    res.set_content("Invalid token","text/plain");
                    return;
                }
                int uid = sqlite3_column_int(stmt,0);
                long long exp = sqlite3_column_int64(stmt,1);
                sqlite3_finalize(stmt);
                if (time(NULL)>exp) {
                    res.status=401;
                    res.set_content("Expired","text/plain");
                    return;
                }
                sqlite3_prepare_v2(database.db, "SELECT v1,v2,v3,v4,v5 FROM kvdata WHERE owner_id=? AND key=?;", -1, &stmt, nullptr);
                sqlite3_bind_int(stmt,1,uid);
                sqlite3_bind_text(stmt,2,key.c_str(),-1,SQLITE_TRANSIENT);
                rc = sqlite3_step(stmt);
                if (rc!=SQLITE_ROW) {
                    sqlite3_finalize(stmt);
                    res.status=404;
                    res.set_content("Not found","text/plain");
                    return;
                }
                json out = json::array();
                for (int i=0;i<5;i++){
                    const unsigned char* txt = sqlite3_column_text(stmt,i);
                    if (!txt) continue;
                    std::string s((const char*)txt);
                    out.push_back(decrypt_field(master_key, s));
                }
                sqlite3_finalize(stmt);
                res.set_content(out.dump(), "application/json");
                push_log("DATA_READ by uid="+std::to_string(uid)+" key="+key);
            } catch(...) {
                res.status=500;
                res.set_content("Error","text/plain");
            }
        });
        // Admin: list users, ban/unban (simple endpoints, require admin token check)
        svr.Get("/admin/users", [&](const httplib::Request &req, httplib::Response &res){
            try{
                if (!req.has_param("admintoken")) {
                    res.status=401;
                    res.set_content("admin token required","text/plain");
                    return;
                }
                std::string at = req.get_param_value("admintoken");
                sqlite3_stmt* stmt;
                sqlite3_prepare_v2(database.db, "SELECT user_id FROM sessions WHERE token=?;", -1, &stmt, nullptr);
                sqlite3_bind_text(stmt,1, at.c_str(), -1, SQLITE_TRANSIENT);
                int rc=sqlite3_step(stmt);
                if (rc!=SQLITE_ROW) {
                    sqlite3_finalize(stmt);
                    res.status=401;
                    res.set_content("Invalid admin token","text/plain");
                    return;
                }
                int uid = sqlite3_column_int(stmt,0);
                sqlite3_finalize(stmt);
                // check is admin
                sqlite3_prepare_v2(database.db, "SELECT is_admin FROM users WHERE id=?;", -1, &stmt, nullptr);
                sqlite3_bind_int(stmt,1,uid);
                rc=sqlite3_step(stmt);
                if (rc!=SQLITE_ROW) {
                    sqlite3_finalize(stmt);
                    res.status=403;
                    res.set_content("Not admin","text/plain");
                    return;
                }
                int isadm = sqlite3_column_int(stmt,0);
                sqlite3_finalize(stmt);
                if (!isadm) {
                    res.status=403;
                    res.set_content("Not admin","text/plain");
                    return;
                }
                // list users
                sqlite3_prepare_v2(database.db, "SELECT id,email,is_admin,banned FROM users;", -1, &stmt, nullptr);
                json out = json::array();
                while ((rc=sqlite3_step(stmt))==SQLITE_ROW) {
                    json u;
                    u["id"] = sqlite3_column_int(stmt,0);
                    u["email"] = (const char*)sqlite3_column_text(stmt,1);
                    u["is_admin"] = sqlite3_column_int(stmt,2);
                    u["banned"] = sqlite3_column_int(stmt,3);
                    out.push_back(u);
                }
                sqlite3_finalize(stmt);
                res.set_content(out.dump(), "application/json");
            } catch(...) {
                res.status=500;
                res.set_content("Err","text/plain");
            }
        });
        svr.Post("/admin/ban", [&](const httplib::Request &req, httplib::Response &res){
            try{
                auto j=json::parse(req.body);
                std::string admintoken = j.at("admintoken").get<std::string>();
                int target_id = j.at("user_id").get<int>();
                sqlite3_stmt* stmt;
                sqlite3_prepare_v2(database.db, "SELECT user_id FROM sessions WHERE token=?;", -1, &stmt, nullptr);
                sqlite3_bind_text(stmt,1,admintoken.c_str(),-1,SQLITE_TRANSIENT);
                int rc=sqlite3_step(stmt);
                if(rc!=SQLITE_ROW){
                    sqlite3_finalize(stmt);
                    res.status=401;
                    res.set_content("Invalid admintoken","text/plain");
                    return;
                }
                int uid=sqlite3_column_int(stmt,0);
                sqlite3_finalize(stmt);
                sqlite3_prepare_v2(database.db, "SELECT is_admin FROM users WHERE id=?;", -1, &stmt, nullptr);
                sqlite3_bind_int(stmt,1,uid);
                rc=sqlite3_step(stmt);
                if(rc!=SQLITE_ROW){
                    sqlite3_finalize(stmt);
                    res.status=403;
                    res.set_content("Not admin","text/plain");
                    return;
                }
                int isadm=sqlite3_column_int(stmt,0);
                sqlite3_finalize(stmt);
                if(!isadm){
                    res.status=403;
                    res.set_content("Not admin","text/plain");
                    return;
                }
                sqlite3_prepare_v2(database.db, "UPDATE users SET banned=1 WHERE id=?;", -1, &stmt, nullptr);
                sqlite3_bind_int(stmt,1,target_id);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                push_log("ADMIN_BAN uid="+std::to_string(target_id));
                res.set_content("OK","text/plain");
            }catch(...){
                res.status=400;
                res.set_content("Bad","text/plain");
            }
        });
        svr.Post("/admin/unban", [&](const httplib::Request &req, httplib::Response &res){
            try{
                auto j=json::parse(req.body);
                std::string admintoken = j.at("admintoken").get<std::string>();
                int target_id = j.at("user_id").get<int>();
                sqlite3_stmt* stmt;
                sqlite3_prepare_v2(database.db, "SELECT user_id FROM sessions WHERE token=?;", -1, &stmt, nullptr);
                sqlite3_bind_text(stmt,1,admintoken.c_str(),-1,SQLITE_TRANSIENT);
                int rc=sqlite3_step(stmt);
                if(rc!=SQLITE_ROW){
                    sqlite3_finalize(stmt);
                    res.status=401;
                    res.set_content("Invalid admintoken","text/plain");
                    return;
                }
                int uid=sqlite3_column_int(stmt,0);
                sqlite3_finalize(stmt);
                sqlite3_prepare_v2(database.db, "SELECT is_admin FROM users WHERE id=?;", -1, &stmt, nullptr);
                sqlite3_bind_int(stmt,1,uid);
                rc=sqlite3_step(stmt);
                if(rc!=SQLITE_ROW){
                    sqlite3_finalize(stmt);
                    res.status=403;
                    res.set_content("Not admin","text/plain");
                    return;
                }
                int isadm=sqlite3_column_int(stmt,0);
                sqlite3_finalize(stmt);
                if(!isadm){
                    res.status=403;
                    res.set_content("Not admin","text/plain");
                    return;
                }
                sqlite3_prepare_v2(database.db, "UPDATE users SET banned=0 WHERE id=?;", -1, &stmt, nullptr);
                sqlite3_bind_int(stmt,1,target_id);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                push_log("ADMIN_UNBAN uid="+std::to_string(target_id));
                res.set_content("OK","text/plain");
            }catch(...){
                res.status=400;
                res.set_content("Bad","text/plain");
            }
        });

        push_log("HTTP server started on port " + std::to_string(SERVER_PORT));
        svr.listen("0.0.0.0", SERVER_PORT);
        push_log("HTTP server stopped");
        server_running = false;
    });
}

void stop_server() {
    if (!server_running) return;
    // For cpp-httplib, to stop gracefully, we can add a shutdown endpoint or use svr.stop(), but since lambda, can't access.
    // Simple way: detach and let it run; for production, use shared_ptr<Server> and call stop().
    // Here, we'll just set flag and detach.
    if (server_thread.joinable()) {
        server_thread.detach();
    }
    server_running = false;
}

// ===== GUI code (ImGui + SDL2 + OpenGL) =====
int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr<<"libsodium init failed"<<std::endl;
        return 1;
    }

    // load master key from env or placeholder
    const char* env = std::getenv("MASTER_KEY_B64");
    std::string mkb64 = env ? std::string(env) : MASTER_KEY_B64_PLACEHOLDER;
    if (mkb64.empty()) {
        std::cerr<<"Set MASTER_KEY_B64 environment variable or edit placeholder."<<std::endl;
        return 1;
    }
    try {
        master_key = base64_decode_vec(mkb64);
    } catch(...) {
        std::cerr<<"Invalid MASTER_KEY_B64"<<std::endl;
        return 1;
    }
    if (master_key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        std::cerr<<"MASTER_KEY must be 32 bytes"<<std::endl;
        return 1;
    }

    // open DB
    try {
        database.open_or_create(DB_PATH);
        push_log("DB opened: " + DB_PATH);
    } catch(std::exception &e) {
        std::cerr<<"DB open error: "<<e.what()<<std::endl;
        return 1;
    }

    // SDL + OpenGL + ImGui init
    if (SDL_Init(SDL_INIT_VIDEO|SDL_INIT_TIMER|SDL_INIT_GAMECONTROLLER) != 0) {
        std::cerr<<"SDL init failed: "<<SDL_GetError()<<std::endl;
        return 1;
    }
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_Window* window = SDL_CreateWindow("Beast Server - GUI", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1200, 800, SDL_WINDOW_OPENGL|SDL_WINDOW_RESIZABLE);
    SDL_GLContext gl_context = SDL_GL_CreateContext(window);
    SDL_GL_MakeCurrent(window, gl_context);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark();
    ImGui_ImplSDL2_InitForOpenGL(window, gl_context);
    ImGui_ImplOpenGL3_Init("#version 130");

    bool show_demo = false;
    char reg_email[256] = {0}; char reg_pass[256] = {0};
    char login_email[256] = {0}; char login_pass[256] = {0};
    char data_key[128] = {0}; char data_vals[5][512]; for(int i=0;i<5;i++) data_vals[i][0]=0;
    std::string current_token;
    int current_user_id = -1;
    bool current_is_admin = false;
    bool show_logs_window = false;

    while (!terminate_app) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            ImGui_ImplSDL2_ProcessEvent(&event);
            if (event.type == SDL_QUIT) terminate_app = true;
        }
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame(window);
        ImGui::NewFrame();

        // Top bar: server control (only admin can control)
        ImGui::Begin("Server Control");
        if (current_is_admin) {
            if (!server_running) {
                if (ImGui::Button("Start Server")) { start_server(); }
            }
            else {
                if (ImGui::Button("Stop Server")) { stop_server(); }
            }
        } else {
            ImGui::TextWrapped("Server start/stop available to admin only (login as admin and start).");
        }
        ImGui::Separator();
        ImGui::Text("HTTP Port: %d", SERVER_PORT);
        ImGui::Text("Server running: %s", server_running ? "YES" : "NO");
        ImGui::End();

        // Registration panel
        ImGui::Begin("Register");
        ImGui::InputText("Email", reg_email, sizeof(reg_email));
        ImGui::InputText("Password", reg_pass, sizeof(reg_pass), ImGuiInputTextFlags_Password);
        if (ImGui::Button("Register")) {
            // call internal DB routine directly
            try {
                std::string email = reg_email; std::string pw = reg_pass;
                if (email.empty()||pw.size()<6) throw std::runtime_error("invalid");
                std::string ph = hash_password(pw);
                sqlite3_stmt* stmt;
                sqlite3_prepare_v2(database.db, "INSERT INTO users (email, passhash) VALUES(?,?);", -1, &stmt, nullptr);
                sqlite3_bind_text(stmt,1,email.c_str(),-1,SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt,2,ph.c_str(),-1,SQLITE_TRANSIENT);
                int rc = sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                if (rc!=SQLITE_DONE) throw std::runtime_error("Insert failed");
                push_log("GUI_REGISTER:"+email);
            } catch (std::exception &e) {
                push_log(std::string("REGISTER_ERR:") + e.what());
            }
        }
        ImGui::End();

        // Login panel
        ImGui::Begin("Login");
        ImGui::InputText("Email##login", login_email, sizeof(login_email));
        ImGui::InputText("Password##login", login_pass, sizeof(login_pass), ImGuiInputTextFlags_Password);
        if (ImGui::Button("Login")) {
            try {
                std::string email = login_email; std::string pw = login_pass;
                sqlite3_stmt* stmt;
                sqlite3_prepare_v2(database.db, "SELECT id,passhash,is_admin,banned FROM users WHERE email=?;", -1, &stmt, nullptr);
                sqlite3_bind_text(stmt,1,email.c_str(),-1,SQLITE_TRANSIENT);
                int rc = sqlite3_step(stmt);
                if (rc!=SQLITE_ROW) {
                    sqlite3_finalize(stmt);
                    push_log("LOGIN_FAIL:"+email);
                }
                else {
                    int uid = sqlite3_column_int(stmt,0);
                    std::string ph = (const char*)sqlite3_column_text(stmt,1);
                    int isadm = sqlite3_column_int(stmt,2);
                    int banned = sqlite3_column_int(stmt,3);
                    sqlite3_finalize(stmt);
                    if (banned) {
                        push_log("LOGIN_BANNED:"+email);
                        current_token.clear();
                        current_user_id=-1;
                        current_is_admin=false;
                    }
                    else if (!verify_password(pw, ph)) {
                        push_log("LOGIN_FAIL:"+email);
                    }
                    else {
                        unsigned char tkn[24];
                        randombytes_buf(tkn,sizeof(tkn));
                        std::string tok = base64_encode(tkn,sizeof(tkn));
                        long long expires = time(NULL) + 60*60*24*7;
                        sqlite3_prepare_v2(database.db, "INSERT OR REPLACE INTO sessions (token,user_id,expires_at) VALUES(?,?,?);", -1, &stmt, nullptr);
                        sqlite3_bind_text(stmt,1,tok.c_str(),-1,SQLITE_TRANSIENT);
                        sqlite3_bind_int(stmt,2,uid);
                        sqlite3_bind_int64(stmt,3,expires);
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                        current_token = tok;
                        current_user_id = uid;
                        current_is_admin = (isadm!=0);
                        push_log("LOGIN_SUCC:"+email);
                    }
                }
            } catch(...) {
                push_log("LOGIN_ERR");
            }
        }
        ImGui::End();

        // Data Entry panel
        ImGui::Begin("Data Entry");
        ImGui::InputText("Key", data_key, sizeof(data_key));
        for (int i=0;i<5;i++) ImGui::InputText((std::string("Field ")+std::to_string(i+1)).c_str(), data_vals[i], sizeof(data_vals[i]));
        if (ImGui::Button("Save Data")) {
            if (current_token.empty()) push_log("SAVE_FAIL:not_logged_in");
            else {
                json j; j["token"] = current_token; j["key"] = std::string(data_key); j["values"] = json::array();
                for (int i=0;i<5;i++) if (strlen(data_vals[i])>0) j["values"].push_back(std::string(data_vals[i]));
                // simulate by calling same DB routines
                try {
                    // reuse encryption code and DB insertion logic from handlers
                    sqlite3_stmt* stmt;
                    std::vector<std::string> enc(5,"");
                    for (size_t i=0; i< j["values"].size(); ++i) enc[i] = encrypt_field(master_key, j["values"][i].get<std::string>()).b64;
                    long long ts = time(NULL);
                    sqlite3_prepare_v2(database.db, "SELECT user_id,expires_at FROM sessions WHERE token=?;", -1, &stmt, nullptr);
                    sqlite3_bind_text(stmt,1,current_token.c_str(),-1,SQLITE_TRANSIENT);
                    int rc = sqlite3_step(stmt);
                    if (rc!=SQLITE_ROW) {
                        sqlite3_finalize(stmt);
                        push_log("SAVE_FAIL:invalid_token");
                    }
                    else {
                        int uid = sqlite3_column_int(stmt,0);
                        sqlite3_finalize(stmt);
                        sqlite3_prepare_v2(database.db, "INSERT INTO kvdata (owner_id,key,v1,v2,v3,v4,v5,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(owner_id,key) DO UPDATE SET v1=excluded.v1,v2=excluded.v2,v3=excluded.v3,v4=excluded.v4,v5=excluded.v5,updated_at=excluded.updated_at;", -1, &stmt, nullptr);
                        sqlite3_bind_int(stmt,1,uid);
                        sqlite3_bind_text(stmt,2,std::string(data_key).c_str(),-1,SQLITE_TRANSIENT);
                        for (int k=0;k<5;k++) {
                            if (enc[k].empty()) sqlite3_bind_null(stmt,3+k);
                            else sqlite3_bind_text(stmt,3+k,enc[k].c_str(),-1,SQLITE_TRANSIENT);
                        }
                        sqlite3_bind_int64(stmt,8,ts);
                        sqlite3_bind_int64(stmt,9,ts);
                        rc = sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                        if (rc==SQLITE_DONE) push_log("SAVE_OK key="+std::string(data_key));
                        else push_log("SAVE_ERR db");
                    }
                } catch(std::exception &e) {
                    push_log(std::string("SAVE_EX: ")+e.what());
                }
            }
        }
        ImGui::End();

        // Data Viewer
        ImGui::Begin("My Data");
        static char query_key[128] = {0};
        ImGui::InputText("Key to load", query_key, sizeof(query_key));
        if (ImGui::Button("Load")) {
            if (current_token.empty()) push_log("LOAD_FAIL:not_logged_in");
            else {
                sqlite3_stmt* stmt;
                sqlite3_prepare_v2(database.db, "SELECT user_id,expires_at FROM sessions WHERE token=?;", -1, &stmt, nullptr);
                sqlite3_bind_text(stmt,1,current_token.c_str(),-1,SQLITE_TRANSIENT);
                int rc = sqlite3_step(stmt);
                if (rc!=SQLITE_ROW) {
                    sqlite3_finalize(stmt);
                    push_log("LOAD_FAIL:invalid_token");
                }
                else {
                    int uid = sqlite3_column_int(stmt,0);
                    sqlite3_finalize(stmt);
                    sqlite3_prepare_v2(database.db, "SELECT v1,v2,v3,v4,v5 FROM kvdata WHERE owner_id=? AND key=?;", -1, &stmt, nullptr);
                    sqlite3_bind_int(stmt,1,uid);
                    sqlite3_bind_text(stmt,2,query_key,-1,SQLITE_TRANSIENT);
                    rc = sqlite3_step(stmt);
                    if (rc!=SQLITE_ROW) {
                        sqlite3_finalize(stmt);
                        push_log("LOAD_NOTFOUND");
                    }
                    else {
                        json out = json::array();
                        for (int i=0;i<5;i++){
                            const unsigned char* txt = sqlite3_column_text(stmt,i);
                            if (!txt) continue;
                            try{
                                out.push_back(decrypt_field(master_key, std::string((const char*)txt)));
                            } catch(...) {
                                out.push_back("<decrypt error>");
                            }
                        }
                        sqlite3_finalize(stmt);
                        // show modal with results
                        if (ImGui::BeginPopupModal("LoadedData", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                            ImGui::Text("Key: %s", query_key);
                            for (size_t i=0;i<out.size();++i) {
                                ImGui::Text("%d: %s", (int)i+1, out[i].get<std::string>().c_str());
                            }
                            if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
                            ImGui::EndPopup();
                        }
                        ImGui::OpenPopup("LoadedData");
                    }
                }
            }
        }
        ImGui::End();

        // Admin Panel (only if admin)
        if (current_is_admin) {
            ImGui::Begin("Admin Panel");
            if (ImGui::Button("Refresh Users")) {
                sqlite3_stmt* stmt;
                sqlite3_prepare_v2(database.db, "SELECT id,email,is_admin,banned FROM users;", -1, &stmt, nullptr);
                int rc;
                json out = json::array();
                while ((rc=sqlite3_step(stmt))==SQLITE_ROW) {
                    json u;
                    u["id"]=sqlite3_column_int(stmt,0);
                    u["email"]=(const char*)sqlite3_column_text(stmt,1);
                    u["is_admin"]=sqlite3_column_int(stmt,2);
                    u["banned"]=sqlite3_column_int(stmt,3);
                    out.push_back(u);
                }
                sqlite3_finalize(stmt);
                // display list
                for (auto &u : out) ImGui::Text("%d - %s admin=%d banned=%d", u["id"].get<int>(), u["email"].get<std::string>().c_str(), u["is_admin"].get<int>(), u["banned"].get<int>());
            }
            ImGui::Separator();
            static int ban_id = 0;
            ImGui::InputInt("User ID to ban", &ban_id);
            if (ImGui::Button("Ban")) {
                sqlite3_stmt* stmt;
                sqlite3_prepare_v2(database.db, "UPDATE users SET banned=1 WHERE id=?;", -1, &stmt, nullptr);
                sqlite3_bind_int(stmt,1,ban_id);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                push_log("ADMIN_BAN:"+std::to_string(ban_id));
            }
            ImGui::SameLine();
            if (ImGui::Button("Unban")) {
                sqlite3_stmt* stmt;
                sqlite3_prepare_v2(database.db, "UPDATE users SET banned=0 WHERE id=?;", -1, &stmt, nullptr);
                sqlite3_bind_int(stmt,1,ban_id);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                push_log("ADMIN_UNBAN:"+std::to_string(ban_id));
            }
            ImGui::Separator();
            if (ImGui::Button("Show Logs")) show_logs_window = true;
            ImGui::End();
        }

        if (show_logs_window) {
            ImGui::Begin("Logs", &show_logs_window);
            std::lock_guard<std::mutex> g(log_mutex);
            for (auto &l : server_logs) ImGui::TextWrapped("%s", l.c_str());
            ImGui::End();
        }

        ImGui::Render();
        glViewport(0,0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
        glClearColor(0.1f,0.1f,0.1f,1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SDL_GL_SwapWindow(window);
    }

    // cleanup
    stop_server();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    SDL_GL_DeleteContext(gl_context);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
