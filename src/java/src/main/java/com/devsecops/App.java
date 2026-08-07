package com.devsecops;

import java.io.*;
import java.sql.*;
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import java.net.*;

/**
 * Vulnerable code samples — intentional SAST findings for CodeQL.
 * NOT a runnable Spring Boot app — just source code for static analysis.
 * DO NOT deploy to production.
 *
 * Vulnerabilities:
 *   1. SQL Injection         — user input in raw SQL query
 *   2. Command Injection     — user input passed to Runtime.exec()
 *   3. Path Traversal        — user-controlled file path
 *   4. Hardcoded Credentials — DB password in source
 *   5. XXE                   — XML parser with external entities enabled
 *   6. SSRF                  — user-controlled URL fetched server-side
 */
public class App {

    // VULNERABILITY 1: Hardcoded credentials
    // CodeQL: java/hardcoded-password-field
    private static final String DB_PASSWORD = "supersecret123";
    private static final String API_KEY     = "sk-prod-abc123xyz";

    // VULNERABILITY 2: SQL Injection
    // CodeQL: java/sql-injection
    public String getUser(String username) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", DB_PASSWORD);
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return String.valueOf(rs.next());
    }

    // VULNERABILITY 3: Command Injection
    // CodeQL: java/command-line-injection
    public String ping(String host) throws Exception {
        Runtime rt = Runtime.getRuntime();
        Process proc = rt.exec("ping -c 1 " + host);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(proc.getInputStream()));
        return reader.readLine();
    }

    // VULNERABILITY 4: Path Traversal
    // CodeQL: java/path-injection
    public String readFile(String filename) throws Exception {
        File file = new File(filename);
        BufferedReader br = new BufferedReader(new FileReader(file));
        return br.readLine();
    }

    // VULNERABILITY 5: XXE
    // CodeQL: java/xxe
    public void parseXml(String xmlInput) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(new InputSource(new StringReader(xmlInput)));
    }

    // VULNERABILITY 6: SSRF
    // CodeQL: java/ssrf
    public String fetchUrl(String url) throws Exception {
        URL targetUrl = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        return reader.readLine();
    }
}
