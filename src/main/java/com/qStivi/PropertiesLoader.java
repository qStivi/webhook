package com.qStivi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

public class PropertiesLoader {

    private static final String PROPERTIES_FILE_PATH = ".properties";
    private static final Logger logger = LoggerFactory.getLogger(PropertiesLoader.class);
    private static PropertiesLoader instance;
    private Properties properties;

    private PropertiesLoader() {
        loadProperties();
    }

    private void loadProperties() {
        properties = new Properties();
        try (FileInputStream fis = new FileInputStream(PROPERTIES_FILE_PATH)) {
            properties.load(fis);
        } catch (FileNotFoundException e) {
            try {
                var created = new File(PROPERTIES_FILE_PATH).createNewFile();
                logger.info("Properties file not found. Properties file created: " + created); // TODO why does this not work?!?!?!?!?!
            } catch (IOException ex) {
                throw new RuntimeException(ex);
                // TODO Handle the exception appropriately
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
            // TODO Handle the exception appropriately
        }
    }

    public static synchronized PropertiesLoader getInstance() {
        if (instance == null) {
            instance = new PropertiesLoader();
        }
        return instance;
    }

    public String getAPIKey(String keyName) {
        return properties.getProperty(keyName);
    }

    public void reloadProperties() {
        loadProperties();
    }
}
