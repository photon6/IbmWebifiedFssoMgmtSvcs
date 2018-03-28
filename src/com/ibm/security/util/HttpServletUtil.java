package com.ibm.security.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.InputMismatchException;
import java.util.List;
import java.util.Map.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.print.attribute.TextSyntax;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.ibm.util.CryptoUtil;

public class HttpServletUtil {
	
	private static KeyStore keyStore = null;
	private static TrustManagerFactory tmf;
	private static SSLContext ctx;
	private static SSLSocketFactory sslFactory;
	
	private final static String[] httpProtocols = new String[]{"https://", "http://"};
	
	public static void initialize(String keystore, String keystorePassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyManagementException {
		
		keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(new FileInputStream(keystore), keystorePassword.toCharArray());
		
		
		tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(keyStore);
		ctx = SSLContext.getInstance("TLS");
		ctx.init(null, tmf.getTrustManagers(), null);
		sslFactory = ctx.getSocketFactory();
	}
	
	public static String consumeJsonRestService(String url, String username, String password, String keyfile, boolean encrypted) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		URLConnection connection = null;
		HttpURLConnection httpConn = null;
		
		String httpHeader_username = "username";
		String httpHeader_password = "password";
		
//		InputStream in = uc.getInputStream();
		
    	StringBuilder sb = new StringBuilder();
		
		try {

			
			connection = new URL(url).openConnection();
			
			httpConn = (HttpURLConnection) connection;
			httpConn.setRequestMethod("GET");
			httpConn.setFollowRedirects(true);
			
			httpConn.setRequestProperty("Accept", "application/json");

			String userpass = username + ":" + (encrypted?CryptoUtil.decrypt(password, new File(keyfile)):password);
			String basicAuth = "Basic " + new String(Base64.getEncoder().encodeToString(username.getBytes()));
			Logger.debug("Creds for service: " + basicAuth);
			httpConn.setRequestProperty ("Authorization", basicAuth);
			
			int responseCode = httpConn.getResponseCode();
			Logger.debug("HTTP Response Code: " + responseCode);
			
			String response = httpConn.getResponseMessage();
			Logger.debug("HTTP Response Message: " + responseCode);
			
			for (Entry<String, List<String>> header : connection.getHeaderFields().entrySet()) {
				
				Logger.debug("Response header: " + (header.getKey() + "=" + header.getValue()));
			}
				
		    try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
		        for (String line; (line = reader.readLine()) != null;) {
		        	sb.append(line + "\n\r");
		        }
		        Logger.debug("From Response: " + sb.toString());
		    }
		
		} catch (IOException e) {
			
//			if (e.getMessage().startsWith("Server returned HTTP response code: 500 for URL")) {
				Logger.debug("Caught Exception: " + e.getMessage());				
//				StackTraceElement[] ste = e.getStackTrace();
//				for (int i = 0; i < ste.length; i++) {
//					Logger.debug(ste[i].getClassName() + "." + ste[i].getMethodName() + "(" + ste[i].getLineNumber() + ")");
//				}

//			} else 
				throw e;
			
		} 

			
		

		return sb.toString();
	}
	
	public static String doGetProxy(String url, HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		URLConnection connection = null;
		HttpURLConnection httpConn = null;
    	StringBuilder sb = new StringBuilder();
		
		try {
			connection = new URL(url).openConnection();
			httpConn = (HttpURLConnection) connection;
		
		} catch (IOException e) {
			if (e.getMessage().startsWith("Server returned HTTP response code: 500 for URL")) {
				Logger.debug("Caught Exception: " + e.getMessage());
			} else throw e;
			
		} 

		int responseCode = httpConn.getResponseCode();
			
		Logger.debug("HTTP Response Code: " + responseCode);
		
		for (Entry<String, List<String>> header : connection.getHeaderFields().entrySet()) {
				
			Logger.debug("Response header: " + (header.getKey() + "=" + header.getValue()));
		}
			
	    try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
	        for (String line; (line = reader.readLine()) != null;) {
	        	sb.append(line + "\n\r");
	        }
	        Logger.debug("From Response: " + sb.toString());
	    }

		return sb.toString();
	

	}
	
	public static String buildRedirectURL(String newHost, HttpServletRequest request) {
    	Logger.debug("Inside method: " + HttpServletUtil.class.getName() 
    			+ "buildRedirectURL(String newHost, HttpServletRequest request)");
    	
    	Logger.debug("New host: " + newHost);
    	Logger.debug("Request Context Path: " + request.getContextPath());
    	Logger.debug("Request Servlet Path: " + request.getServletPath());
		
		String redirectURL = newHost + request.getContextPath() + request.getServletPath() + "?" + request.getQueryString();
//		String paramName, urlSuffix = "";
//		String[] paramVals;
//		StringBuilder sb = null;
//		
//    	Enumeration<String> paramNames = request.getParameterNames();
//    	while (paramNames.hasMoreElements()) {
//    		paramName = paramNames.nextElement();
//    		paramVals = request.getParameterValues(paramName);
//    		if (paramVals.length  > 0) sb = new StringBuilder();
//    		for (int i = 0; i < paramVals.length; i++) {
//				sb.append(paramVals[i]);
////				if (paramVals.length < (i+1)) sb.append("&");
//			}
//    		urlSuffix = ((sb == null)?"":(paramName + "=" + sb.toString()));
//    		Logger.debug("Request parameter: " + urlSuffix);
//    	}
//    	
//    	redirectURL += "?" + urlSuffix;
    	
    	Logger.debug("Redirect URL:" + redirectURL);
    	
    	return redirectURL;
		
	}
	
    public static void logRequestInfo(HttpServletRequest request) throws InputMismatchException, IOException {    	
    	Logger.debug("Inside method: " + HttpServletUtil.class.getName() 
    			+ "logRequestInfo(HttpServletRequest request)");
    	
    	String headerName = "", attribName = "", paramName = "", username1 = "";
    	String[] paramVals;
    	StringBuilder sb = null;
		
    	Enumeration<String> requestHeaderNames = request.getHeaderNames();
    	while (requestHeaderNames.hasMoreElements()) {
    		headerName = requestHeaderNames.nextElement();
    		Logger.debug("Request header: " + headerName + " = " + request.getHeader(headerName));
    	}
    	
    	Enumeration<String> attribNames = request.getAttributeNames();
    	while (attribNames.hasMoreElements()) {
    		attribName = attribNames.nextElement();
    		Logger.debug("Request attributes: " + attribName + " = " + request.getHeader(attribName));
    	}
    	

    	Enumeration<String> paramNames = request.getParameterNames();
    	while (paramNames.hasMoreElements()) {
    		paramName = paramNames.nextElement();
    		paramVals = request.getParameterValues(paramName);
    		if (paramVals.length  > 0) sb = new StringBuilder();
    		for (int i = 0; i < paramVals.length; i++) {
				sb.append(paramVals[i]);
				if (paramVals.length < (i+1)) sb.append("\n\r");
			}
    		Logger.debug("Request parameter: " + paramName + " = " + ((sb == null)?"":sb.toString()));
    	}
    	
    	Logger.debug("Request Path Info: " + request.getPathInfo());
    	Logger.debug("Request Servlet Path: " + request.getServletPath());
    	Logger.debug("Request Query string: " + request.getQueryString());

    	Logger.debug("User Principal: " + request.getUserPrincipal());
    	Logger.debug("Session ID: " + request.getSession().getId());
    	Logger.debug("AuthType: " + request.getAuthType());
    	Logger.debug("Context path: " + request.getContextPath());
    	
    	username1 = request.getHeader("IV-USER");
    	Logger.debug("username1: " + username1);
    	
    	if (username1 != null) {
    		if (!username1.equals("") & !username1.equals("null")) {
    			Logger.audit(username1 + " has invoked " + request.getServletPath());
    			String textToWrite = "[" + new SimpleDateFormat(PropertiesManager.getApplicationProperty("W3ID_UTIL_DATETIME_FORMAT_LOG")).format(new Date()) + "] " + username1 + " invoked " + request.getServletPath() + "?" + request.getQueryString() + System.lineSeparator();
    			FileUtil.writeToFile(PropertiesManager.getApplicationProperty("W3ID_UTIL_AUDIT_LOG_FILE"), textToWrite, false);
    		}
    	}
    	
    }

    public static String parseHostNameFromURL(String url) {
    	Logger.debug("Inside method: " + HttpServletUtil.class.getName() 
    			+ ".parseHostNameFromURL(String url)");
    	
    	for (String httpProtocol : httpProtocols) {
        	if (url.contains(httpProtocol)) {
        		Logger.debug("Removing " + httpProtocol + " in " + url);
        		url = url.replaceAll(httpProtocol, "");
        	}
		}
    	
		Logger.debug("Removing domain from " + url);
    	url = url.substring(0, url.indexOf("."));
    	
    	return url;
    	
    	
    }
    

}
