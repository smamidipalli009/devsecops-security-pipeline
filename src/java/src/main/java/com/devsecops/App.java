package com.devsecops;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.sql.*;
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import java.net.*;

/**
 * Vulnerable Spring Boot application — intentional SAST findings for CodeQL.
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
@SpringBootApplication
@RestController
public class App {

    // VULNERABILITY 1: Hardcoded credentials
    // CodeQL: java/hardcoded-password-field
    private static final String DB_PASSWORD = "supersecret123";
    private static final String API_KEY     = "sk-prod-abc123xyz";

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }

    @GetMapping("/")
    public String index() {
        return "{\"status\":\"ok\",\"message\":\"Java DevSecOps demo app\"}";
    }

    @GetMapping("/health")
    public String health() {
        return "{\"status\":\"healthy\"}";
    }

    // VULNERABILITY 2: SQL Injection
    // CodeQL: java/sql-injection
    @GetMapping("/user")
    public String getUser(@RequestParam String username) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", DB_PASSWORD);
        // BAD: string concatenation directly into SQL
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return "{\"result\":\"" + rs.next() + "\"}";
    }

    // VULNERABILITY 3: Command Injection
    // CodeQL: java/command-line-injection
    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws Exception {
        // BAD: user input passed directly to shell
        Runtime rt = Runtime.getRuntime();
        Process proc = rt.exec("ping -c 1 " + host);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(proc.getInputStream()));
        return "{\"output\":\"" + reader.readLine() + "\"}";
    }

    // VULNERABILITY 4: Path Traversal
    // CodeQL: java/path-injection
    @GetMapping("/file")
    public String readFile(@RequestParam String filename) throws Exception {
        // BAD: user controls the file path — can read /etc/passwd etc.
        File file = new File(filename);
        BufferedReader br = new BufferedReader(new FileReader(file));
        return "{\"content\":\"" + br.readLine() + "\"}";
    }

    // VULNERABILITY 5: XXE (XML External Entity)
    // CodeQL: java/xxe
    @PostMapping("/xml")
    public String parseXml(@RequestBody String xmlInput) throws Exception {
        // BAD: DocumentBuilderFactory with external entities enabled
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Missing: dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(new InputSource(new StringReader(xmlInput)));
        return "{\"status\":\"parsed\"}";
    }

    // VULNERABILITY 6: SSRF (Server Side Request Forgery)
    // CodeQL: java/ssrf
    @GetMapping("/fetch")
    public String fetchUrl(@RequestParam String url) throws Exception {
        // BAD: user-controlled URL fetched directly
        URL targetUrl = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        return "{\"content\":\"" + reader.readLine() + "\"}";
    }
}
