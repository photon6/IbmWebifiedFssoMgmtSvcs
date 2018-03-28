package com.ibm.security.util;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.spi.LoggerContextFactory;

public class Logger {
	
	
	private static org.apache.logging.log4j.Logger logger = LogManager.getLogger();
	private static String currentLevel = logger.getLevel().name();
	
	public static void debug(String msg) {
		logger.debug(msg);
	}
	
	public static void audit(String msg) {
		logger.info(msg);
		logger.error(msg);
		logger.debug(msg);
		logger.warn(msg);
	}
	
	public static void info(String msg) {
		logger.info(msg);
	}
	
	public static void logToAllLevels(String msg) {
		logger.log(Level.ALL, msg);
		System.out.println(msg);
	}
	
	public static void reloadLogger() {
		
		
		LogManager.shutdown();
		logger = LogManager.getLogger();
		
		LoggerContext ctx = (LoggerContext) LogManager.getContext(false);		
		Configuration config = ctx.getConfiguration();
		ConcurrentHashMap<String, Appender> appenders = (ConcurrentHashMap<String, Appender>) config.getAppenders();
		
		
		Enumeration<String> keys = appenders.keys();
		while (keys.hasMoreElements()) {
			String key = (String) keys.nextElement();
			Logger.debug("Reinitializing appender: " + key);
			appenders.get(key).initialize();
		}
		
		currentLevel = logger.getLevel().name();
		
		Logger.debug("Reloaded logger. Current log level: " + currentLevel);

	}
	
	public static String getCurrentLogLevel() {
		return currentLevel;
	}
	

}

