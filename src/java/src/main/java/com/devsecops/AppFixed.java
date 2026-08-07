package com.devsecops;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.sql.*;
import javax.xml.parsers.*;
import java.util.Arrays;

/**
 * Hardened Spring Boot application — all SAST findings from App.java fixed.
 *
 * Fixes applied:
 *   1. Hardcoded Credentials → loaded from environment variables
 *   2. SQL Injection         → PreparedStatement with ? placeholder
 *   3. Command Injection     → ProcessBuilder with list args
 *   4. Path Traversal        → Path.normalize() + safe directory check
 *   5. XXE                   → DocumentBuilderFactory with DOCTYPE disabled
 *   6. SSRF                  → allowlist of permitted hosts
 */
@SpringBootApplication
@RestController
public class AppFixed {

    // FIX 1: Credentials from environment variables
    private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");
    private static final String API_KEY     = System.getenv("API_KEY");
    private static final String SAFE_DIR    = "/app/safe_files";
    private static final java.util.List<String> ALLOWED_HOSTS =
        Arrays.asList("api.example.com", "data.example.com");

    public static void main(String[] args) {
        SpringApplication.run(AppFixed.class, args);
    }

    @GetMapping("/")
    public String index() {
        return "{\"status\":\"ok\",\"message\":\"Java DevSecOps demo app (hardened)\"}";
    }

    @GetMapping("/health")
    public String health() {
        return "{\"status\":\"healthy\"}";
    }

    // FIX 2: Parameterised query — SQL injection not possible
    @GetMapping("/user")
    public String getUser(@RequestParam String username) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", DB_PASSWORD);
        PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM users WHERE username = ?");
        ps.setString(1, username);
        ResultSet rs = ps.executeQuery();
        return "{\"result\":\"" + rs.next() + "\"}";
    }

    // FIX 3: ProcessBuilder with list args — command injection not possible
    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(proc.getInputStream()));
        return "{\"output\":\"" + reader.readLine() + "\"}";
    }

    // FIX 4: Path normalisation + safe directory check
    @GetMapping("/file")
    public String readFile(@RequestParam String filename) throws Exception {
        Path safePath = Paths.get(SAFE_DIR).resolve(filename).normalize();
        if (!safePath.startsWith(SAFE_DIR)) {
            return "{\"error\":\"Access denied\"}";
        }
        return "{\"content\":\"" + Files.readString(safePath) + "\"}";
    }

    // FIX 5: XXE disabled — DOCTYPE declarations blocked
    @PostMapping("/xml")
    public String parseXml(@RequestBody String xmlInput) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(new org.xml.sax.InputSource(new StringReader(xmlInput)));
        return "{\"status\":\"parsed\"}";
    }

    // FIX 6: SSRF prevented — host allowlist enforced
    @GetMapping("/fetch")
    public String fetchUrl(@RequestParam String url) throws Exception {
        java.net.URL targetUrl = new java.net.URL(url);
        if (!ALLOWED_HOSTS.contains(targetUrl.getHost())) {
            return "{\"error\":\"Host not permitted\"}";
        }
        java.net.HttpURLConnection conn =
            (java.net.HttpURLConnection) targetUrl.openConnection();
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        return "{\"content\":\"" + reader.readLine() + "\"}";
    }
}
