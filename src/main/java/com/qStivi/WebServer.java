package com.qStivi;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class WebServer {

    private static final Logger logger = LoggerFactory.getLogger(WebServer.class);

    private static final int PORT = 8000;
    private static final String SECRET_TOKEN = PropertiesLoader.getInstance().getAPIKey("secretToken");

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/webhook", new WebhookHandler());
        server.start();
        logger.info("Server started on port " + PORT);
    }

    public static class WebhookHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            logger.info("Received a webhook request");
            if ("POST".equals(exchange.getRequestMethod())) {
                // Read the request body
                String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

                // Verify the secret token
                String signature = exchange.getRequestHeaders().getFirst("x-hub-signature-256");
                if (isValidSignature(requestBody, signature, SECRET_TOKEN)) {
                    // Secret token is valid, process the request body
                    logger.info("Request body: " + requestBody);

                    // Further processing of the request body...

                    // Send a response
                    String response = "Webhook received";
                    exchange.sendResponseHeaders(200, response.getBytes(StandardCharsets.UTF_8).length);
                    OutputStream responseBody = exchange.getResponseBody();
                    responseBody.write(response.getBytes(StandardCharsets.UTF_8));
                    responseBody.close();
                } else {
                    // Invalid secret token, handle accordingly
                    logger.error("Invalid secret token");

                    // Send an error response
                    String response = "Unauthorized";
                    exchange.sendResponseHeaders(401, response.getBytes(StandardCharsets.UTF_8).length);
                    OutputStream responseBody = exchange.getResponseBody();
                    responseBody.write(response.getBytes(StandardCharsets.UTF_8));
                    responseBody.close();
                }
            } else {
                // Handle other HTTP methods if needed
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                exchange.close();
            }
        }

        private boolean isValidSignature(String requestBody, String signature, String secretToken) {
            if (signature == null || !signature.startsWith("sha256=")) {
                return false;
            }

            String algorithm = signature.substring(7);
            try {
                byte[] secretKeyBytes = secretToken.getBytes(StandardCharsets.UTF_8);
                byte[] requestBodyBytes = requestBody.getBytes(StandardCharsets.UTF_8);

                Mac sha256Hmac = Mac.getInstance("HmacSHA256");
                sha256Hmac.init(new SecretKeySpec(secretKeyBytes, algorithm));

                byte[] calculatedHash = sha256Hmac.doFinal(requestBodyBytes);
                String calculatedDigest = "sha256=" + bytesToHex(calculatedHash);

                return secureCompare(signature, calculatedDigest);
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                // Handle the exception appropriately
                return false;
            }
        }

        private String bytesToHex(byte[] bytes) {
            StringBuilder result = new StringBuilder();
            for (byte b : bytes) {
                result.append(String.format("%02x", b));
            }
            return result.toString();
        }

        private boolean secureCompare(String a, String b) {
            if (a.length() != b.length()) {
                return false;
            }

            int result = 0;
            for (int i = 0; i < a.length(); i++) {
                result |= a.charAt(i) ^ b.charAt(i);
            }
            return result == 0;
        }
    }
}
