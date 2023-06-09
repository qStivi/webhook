package com.qStivi;

import com.sun.tools.javac.Main;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.Request;
import spark.Response;
import spark.Route;
import spark.Spark;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class WebhookServer {

    private static final String SECRET_TOKEN = PropertiesLoader.getInstance().getAPIKey("secretToken");
    private static final Logger logger = LoggerFactory.getLogger(WebhookServer.class);

    public static void main(String[] args) {
        try {
            Spark.port(8000);
            Spark.webSocketIdleTimeoutMillis(0);

            // Set up the route to handle the webhook
            Spark.post("/webhook", new WebhookHandler());

            // Start the server
            Spark.awaitInitialization();
            Spark.exception(Exception.class, (exception, request, response) -> {
                logger.error("Exception occurred", exception);
                response.status(500);
                response.body("Internal server error");
                Spark.halt();
            });
            logger.info("Server started on port 8000");
        } catch (Exception e) {
            logger.error("Server failed to start", e);
        }
    }

    public static class WebhookHandler implements Route {

        @Override
        public Object handle(Request request, Response response) throws Exception {
            if ("POST".equals(request.requestMethod())) {
                // Read the request body
                String requestBody = request.body();

                // Verify the secret token
                String signature = request.headers("x-hub-signature-256");
                if (isValidSignature(requestBody, signature, SECRET_TOKEN)) {
                    // Secret token is valid, process the request body
                    logger.info("Request body: " + requestBody);

                    // Further processing of the request body...

                    // Send a response
                    response.status(200);
                    return "Webhook received";
                } else {
                    // Invalid secret token, handle accordingly
                    logger.info("Invalid secret token");

                    // Send an error response
                    response.status(401);
                    return "Unauthorized";
                }
            } else {
                // Handle other HTTP methods if needed
                response.status(405);
                return "Method Not Allowed";
            }
        }

        private boolean isValidSignature(String requestBody, String signature, String secretToken) throws Exception {
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

        private String bytesToHex(byte[] bytes) throws Exception {
            StringBuilder result = new StringBuilder();
            for (byte b : bytes) {
                result.append(String.format("%02x", b));
            }
            return result.toString();
        }

        private boolean secureCompare(String a, String b) throws Exception {
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
