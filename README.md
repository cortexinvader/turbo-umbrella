# 🔔 Everything in the project is written by Ai just for test 🤦

To get the **Beast C++ SQLite Server** working on a Windows system, you need to set up the environment, install dependencies, provide required libraries, and configure the application. Below is a detailed step-by-step guide on what you need to install, add, and configure to make it work.

---

### 1. Install Development Environment (MSYS2 MinGW64)
The code is designed to be compiled using MSYS2 with MinGW64. Follow these steps:

- **Install MSYS2**:
  - Download the MSYS2 installer from [msys2.org](https://www.msys2.org/) and follow the installation instructions.
  - Choose the 64-bit version (`msys2-x86_64-<version>.exe`).
  - Install it to a directory like `C:\msys64`.

- **Update MSYS2**:
  - Open the MSYS2 MinGW64 terminal (run `C:\msys64\mingw64.exe`).
  - Update the package database and core packages:
    ```bash
    pacman -Syu
    ```
    If prompted to close the terminal, do so, reopen it, and run the command again to complete the update.

- **Install Required Toolchain and Dependencies**:
  Run the following command in the MSYS2 MinGW64 terminal to install the compiler and libraries specified in the build command:
  ```bash
  pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-sdl2 mingw-w64-x86_64-glew mingw-w64-x86_64-sqlite3 mingw-w64-x86_64-libsodium
  ```
  This installs:
  - `mingw-w64-x86_64-toolchain`: Includes `g++`, `gcc`, and other tools for compiling C++ code.
  - `mingw-w64-x86_64-sdl2`: SDL2 library for the GUI (windowing and input).
  - `mingw-w64-x86_64-glew`: OpenGL Extension Wrangler for OpenGL functionality.
  - `mingw-w64-x86_64-sqlite3`: SQLite library for database operations.
  - `mingw-w64-x86_64-libsodium`: Libsodium for encryption and password hashing.

---

### 2. Add Required Single-Header Libraries
The code depends on two single-header libraries that must be placed in your project's include path:

- **cpp-httplib (`httplib.h`)**:
  - Download the latest `httplib.h` from the [cpp-httplib GitHub repository](https://github.com/yhirose/cpp-httplib).
  - Place it in your project directory, e.g., `C:\beast_server\include\httplib.h`, or in a directory included in your compiler's include path (e.g., `C:\msys64\mingw64\include`).

- **nlohmann/json (`json.hpp`)**:
  - Download the latest `json.hpp` from the [nlohmann/json GitHub repository](https://github.com/nlohmann/json).
  - Place it in your project directory, e.g., `C:\beast_server\include\nlohmann\json.hpp`, or in the include path.

---

### 3. Add ImGui Sources
The code uses Dear ImGui for the GUI, along with its SDL2 and OpenGL3 backends. You need to include these source files:

- **Download ImGui**:
  - Go to the [Dear ImGui GitHub repository](https://github.com/ocornut/imgui) and download the latest release or clone the repository.
  - Copy the following files to a `vendor/imgui` directory in your project (e.g., `C:\beast_server\vendor\imgui`):
    - `imgui.h`
    - `imgui.cpp`
    - `imgui_draw.cpp`
    - `imgui_widgets.cpp`
    - `imgui_tables.cpp`
    - `imgui_internal.h`
    - `imconfig.h`
    - `backends/imgui_impl_sdl.h`
    - `backends/imgui_impl_sdl.cpp`
    - `backends/imgui_impl_opengl3.h`
    - `backends/imgui_impl_opengl3.cpp`

- **Directory Structure**:
  Ensure your project directory looks like this:
  ```
  C:\beast_server\
  ├── beast_gui_server.cpp  (the provided source code)
  ├── include\
  │   ├── httplib.h
  │   └── nlohmann\
  │       └── json.hpp
  └── vendor\
      └── imgui\
          ├── imgui.h
          ├── imgui.cpp
          ├── imgui_draw.cpp
          ├── imgui_widgets.cpp
          ├── imgui_tables.cpp
          ├── imgui_internal.h
          ├── imconfig.h
          ├── backends\
          │   ├── imgui_impl_sdl.h
          │   ├── imgui_impl_sdl.cpp
          │   ├── imgui_impl_opengl3.h
          │   └── imgui_impl_opengl3.cpp
  ```

- **Include Path**:
  When compiling, ensure the compiler can find these headers. You may need to add `-I.` to the build command if the `include` and `vendor` directories are in your project root.

---

### 4. Configure the Master Key
The application requires a 32-byte master key (encoded in base64) for encryption. You must set the `MASTER_KEY_B64` environment variable or edit the `MASTER_KEY_B64_PLACEHOLDER` constant in the code.

- **Option 1: Set Environment Variable**:
  - Generate a 32-byte key in base64 format:
    ```bash
    openssl rand -base64 32
    ```
    Example output: `3fXj9y8vK2zL5mNqP4rT7uWvX0yZ2aB3cD4eF6gH8iJ=`
  - Set the environment variable in your MSYS2 terminal before running the program:
    ```bash
    export MASTER_KEY_B64="3fXj9y8vK2zL5mNqP4rT7uWvX0yZ2aB3cD4eF6gH8iJ="
    ```
  - Alternatively, set it permanently in Windows:
    - Open the Start menu, search for "environment variables," and select "Edit the system environment variables."
    - Add a new variable named `MASTER_KEY_B64` with the base64 key as its value.

- **Option 2: Edit the Code**:
  - Edit the `MASTER_KEY_B64_PLACEHOLDER` constant in the code:
    ```cpp
    static const std::string MASTER_KEY_B64_PLACEHOLDER = "3fXj9y8vK2zL5mNqP4rT7uWvX0yZ2aB3cD4eF6gH8iJ=";
    ```
  - **Warning**: Do not commit this key to version control (e.g., Git) to avoid security risks.

---

### 5. Create Database Directory
The code uses a SQLite database stored at `C:/beast_server/mydatabase.db`. Ensure the directory exists:

- Create the folder:
  ```bash
  mkdir -p C:/beast_server
  ```

- Verify the path in the code:
  ```cpp
  static const std::string DB_PATH = "C:/beast_server/mydatabase.db";
  ```
  If you want to use a different path, update this constant in the code.

---

### 6. Compile the Application
Once the dependencies and headers are set up, compile the code using the provided command, adjusted for your project structure.

- **Navigate to Project Directory**:
  In the MSYS2 MinGW64 terminal, go to your project directory:
  ```bash
  cd /c/beast_server
  ```

- **Compile Command**:
  ```bash
  g++ -std=c++17 beast_gui_server.cpp vendor/imgui/*.cpp vendor/imgui/backends/imgui_impl_sdl.cpp vendor/imgui/backends/imgui_impl_opengl3.cpp -I. -o beast_gui_server.exe -lSDL2 -lSDL2main -lopengl32 -lsqlite3 -lsodium -lws2_32 -lgdi32
  ```
  - `-I.`: Includes the current directory for header files (adjust if `include` and `vendor` are elsewhere, e.g., `-IC:/beast_server/include -IC:/beast_server/vendor`).
  - `vendor/imgui/*.cpp`: Compiles all ImGui source files.
  - The output executable will be `beast_gui_server.exe`.

- **Troubleshooting**:
  - If headers are not found, ensure `httplib.h`, `json.hpp`, and ImGui files are in the include path.
  - If libraries are missing, verify that `pacman` installed `SDL2`, `glew`, `sqlite3`, and `libsodium`.
  - If you get linker errors, ensure `-lws2_32` (for Windows sockets) and `-lgdi32` are included.

---

### 7. Run the Application
- **Run the Executable**:
  In the MSYS2 MinGW64 terminal, from the project directory:
  ```bash
  ./beast_gui_server.exe
  ```

- **What to Expect**:
  - A GUI window (1200x800) will open with panels for:
    - **Server Control**: Start/stop the HTTP server (admin only).
    - **Register**: Create a new user with email and password.
    - **Login**: Log in to get a session token.
    - **Data Entry**: Save up to 5 encrypted values under a key.
    - **My Data**: Retrieve and decrypt stored values by key.
    - **Admin Panel** (if logged in as admin): List users, ban/unban users, view logs.
  - The HTTP server (when started) listens on port 8080 for API requests (e.g., `/register`, `/login`, `/data`, `/admin/*`).
  - Logs are written to `server_gui.log` in the project directory.

- **Testing the API**:
  Use tools like `curl` or Postman to interact with the HTTP API:
  - Register: `curl -X POST http://localhost:8080/register -d '{"email":"test@example.com","password":"mypassword"}'`
  - Login: `curl -X POST http://localhost:8080/login -d '{"email":"test@example.com","password":"mypassword"}'`
  - Save data: `curl -X POST http://localhost:8080/data -d '{"token":"your_token","key":"mykey","values":["val1","val2"]}'`
  - Get data: `curl http://localhost:8080/data?token=your_token&key=mykey`

---

### 8. Additional Notes
- **Admin Setup**:
  - The code does not automatically create an admin user. To make a user an admin, manually update the `users` table in the SQLite database (`C:/beast_server/mydatabase.db`):
    ```sql
    UPDATE users SET is_admin=1 WHERE email='your_admin_email';
    ```
    Use a SQLite client like [DB Browser for SQLite](https://sqlitebrowser.org/).

- **Port Conflicts**:
  - Ensure port 8080 is free. If not, change `SERVER_PORT` in the code:
    ```cpp
    static const int SERVER_PORT = 8081; // or another free port
    ```

- **Security**:
  - The master key is critical for encryption/decryption. Store it securely and never expose it.
  - The database (`mydatabase.db`) contains encrypted data and password hashes. Protect it from unauthorized access.
  - Consider adding HTTPS support to `cpp-httplib` (requires OpenSSL) for production use.

- **Logging**:
  - Logs are stored in `server_gui.log` in the project directory. Check this file for debugging.

- **Windows-Specific**:
  - The code uses `ws2_32` for networking, which is Windows-specific. For cross-platform support, additional modifications are needed.
  - Ensure `C:/beast_server` is writable by the application.

---

### 9. Optional: Set Up as a Service
To enable autostart on boot (as mentioned in the code comments), you can run the executable as a Windows service:

- Use a tool like [NSSM (Non-Sucking Service Manager)](https://nssm.cc/):
  ```bash
  nssm install BeastServer C:\beast_server\beast_gui_server.exe
  ```
- Configure the service to start automatically via the Services management console (`services.msc`).

---

### Summary of Requirements
- **Software**:
  - MSYS2 MinGW64
  - Packages: `mingw-w64-x86_64-toolchain`, `mingw-w64-x86_64-sdl2`, `mingw-w64-x86_64-glew`, `mingw-w64-x86_64-sqlite3`, `mingw-w64-x86_64-libsodium`
- **Libraries**:
  - `httplib.h` (cpp-httplib)
  - `json.hpp` (nlohmann/json)
  - ImGui sources (`imgui*.cpp`, `imgui_impl_sdl.*`, `imgui_impl_opengl3.*`)
- **Configuration**:
  - Set `MASTER_KEY_B64` environment variable (or edit `MASTER_KEY_B64_PLACEHOLDER`).
  - Create `C:/beast_server` directory for the database.
- **Build Command**:
  ```bash
  g++ -std=c++17 beast_gui_server.cpp vendor/imgui/*.cpp vendor/imgui/backends/imgui_impl_sdl.cpp vendor/imgui/backends/imgui_impl_opengl3.cpp -I. -o beast_gui_server.exe -lSDL2 -lSDL2main -lopengl32 -lsqlite3 -lsodium -lws2_32 -lgdi32
  ```

With these steps, the application should compile and run, providing both a GUI control panel and an HTTP API for user and data management. If you encounter issues, check the console output or `server_gui.log` for errors, and verify that all paths and dependencies are correctly set.
