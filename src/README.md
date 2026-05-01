# 🛡️ Group 5 Cyber Demonstration Portal

## 📖 Project Description
The **Cyber Demonstration Portal** is an interactive "Hack and Patch" web application designed for educational purposes. It provides a split-view interface where users can execute common cyber attacks on a vulnerable application state, and then immediately observe how secure coding practices and proper backend configurations mitigate those exact attacks. 

This project aims to visually demonstrate the mechanisms behind the OWASP Top 10 vulnerabilities, showcasing both the attacker's perspective (exploitation) and the developer's perspective (remediation).

## 📚 References Studied
We studied and derived inspiration from the following instructor-provided reference projects located in the `learning/cyber_security/` directory:
1. **`unsafe_banking`**: We studied this to understand how weak authentication, string-formatted SQL queries, and missing session validations lead to severe vulnerabilities like IDOR and Business Logic flaws.
2. **`minipay`**: We analyzed the XSS vulnerabilities outlined in this module to understand client-side reflection attacks and how to mitigate them using templating engines.

## 🔐 Security Concepts Implemented
Our portal successfully implements and demonstrates the following critical security concepts:

### 1. SQL Injection (SQLi)
*   **Vulnerable Concept:** Directly concatenating user input into backend SQL strings (e.g., `f"SELECT * FROM users WHERE username='{username}'"`). This allows attackers to manipulate the logic using payloads like `' OR '1'='1' -- `.
*   **Secure Mitigation:** Implementation of **Parameterized Queries** (`"SELECT * FROM users WHERE username=?"`), which forces the database engine to treat user input strictly as literals rather than executable SQL commands.

### 2. Cross-Site Scripting (XSS)
*   **Vulnerable Concept:** Reflecting unvalidated, unescaped user input back into the DOM using tools that disable security (e.g., Flask's `Markup()` function). This allows `<script>` tags to execute JavaScript in the victim's browser.
*   **Secure Mitigation:** Relying on **Context-Aware Auto-Escaping** provided by the Jinja2 templating engine, which securely converts dangerous HTML tags (like `<`) into safe entity references (`&lt;`).

### 3. Insecure Direct Object Reference (IDOR)
*   **Vulnerable Concept:** Fetching sensitive data entirely based on a user-supplied ID parameter without verifying the requester's identity.
*   **Secure Mitigation:** Implementing **Access Control Validations** to ensure `requested_target_id == currently_authenticated_session_id` before querying the database.

### 4. Broken Business Logic
*   **Vulnerable Concept:** Blindly trusting hidden client-side HTML form fields (e.g., `from_account`) to authorize sensitive transactions, like wire transfers.
*   **Secure Mitigation:** Enforcing **Server-Side Authority** by dropping the client-supplied source IDs and hardcoding the source of the transaction to the cryptographically verified session token.

---

## 🚀 Setup & Execution Instructions

1. **Navigate to the Project Directory:**
   ```bash
   cd student_folder/grp5/src/
   ```

2. **Install Dependencies:**
   Ensure you have Python installed, then run:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application:**
   ```bash
   python app.py
   ```
   *(The SQLite database is automatically generated and seeded on the first run).*

4. **Access the Portal:**
   Open your web browser and navigate to: [http://127.0.0.1:5000](http://127.0.0.1:5000)
