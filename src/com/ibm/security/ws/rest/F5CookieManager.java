package com.ibm.security.ws.rest;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.Arrays;
import java.util.StringTokenizer;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.ibm.security.infrastructure.IBMw3idFedSSOF5Management;
import com.ibm.security.infrastructure.IBMw3idFedSSOISAMManagement;
import com.ibm.security.util.HttpServletUtil;
import com.ibm.security.util.JSONUtil;
import com.ibm.security.util.Logger;
import com.ibm.security.util.PropertiesManager;
import com.mifmif.common.regex.Generex;

/**
 * Servlet implementation class F5CookieManager
 */
@WebServlet(name = "decodeF5Cookie", urlPatterns = { "/decodeF5Cookie" })
public class F5CookieManager extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private static final String W3ID_LOGS_KEY_REGEX_PROP="W3ID_LOGS_KEY_REGEX";
	private static final String W3ID_LOGS__KEY_LENGTH_PROP="W3ID_LOGS__KEY_LENGTH";

	private IBMw3idFedSSOF5Management f5Util = null;
	
	private Generex regexUtil;

	
    /**
     * @see HttpServlet#HttpServlet()
     */
    public F5CookieManager() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		Logger.debug("Inside Servlet (" + request.getMethod() + "): " + getServletConfig().getServletName());

		HttpServletUtil.logRequestInfo(request);

		String async = "true";
//		String async = Boolean.toString(!Boolean.parseBoolean(appProps.getProperty("async_boarding")));
//		Logger.debug("async (from property file) = " + async);
		
		try {
			
//			String env = "";
//			try {
//				env = request.getParameter("env").toString();
//			} catch (Exception e) {
//				throw new ServletException("Environment is required: Please supply one of the following: 'env=prod' or 'env=staging' or 'env=test'");
//			}
//			Logger.debug("env = " + env);

			String format = "";
			try {
				format = request.getParameter("fmt").toString();
			} catch (Exception ignoreit) {}
			Logger.debug("format = " + format);
			
			String cookie = "";
			String[] cookies = new String[1];
			try {
				cookie = request.getParameter("cookie").toString();
				
				if (cookie.contains(",")) {
					StringTokenizer st = new StringTokenizer(cookie, ",");
					cookies = new String[st.countTokens()];
					for (int i = 0; st.hasMoreTokens(); i++) {
						cookies[i] = st.nextToken();
					}
				} else {
					cookies[0] = cookie;
				}
				
			} catch (Exception e) {
				throw new ServletException("At least one user ID is required. Comma-separate multiple user IDs");
			}
			Logger.debug("User IDs: " + Arrays.toString(cookies));
			
			boolean saveAsFile = false;
			try {
				saveAsFile = Boolean.parseBoolean(request.getParameter("zipit").toString());
			} catch (Exception ignoreit) {}
			Logger.debug("saveAsFile = " + saveAsFile);
			
			String zipFileName = "";
			if (saveAsFile) {
				zipFileName = generateLogDownloadKey();
			}

			if (f5Util == null) f5Util = new IBMw3idFedSSOF5Management();
			
			String jsonString = f5Util.decodeF5Cookie(cookie);
			response.setContentType("application/json");
			response.getWriter().print(jsonString);

			Logger.debug("Setting HTTP Response Access-Control-Allow-Origin: *");
			response.setHeader("Access-Control-Allow-Origin", "*");
			
//			if (obj instanceof String) {
//				String jsonString = (String) obj;
//			} else if (obj instanceof File) {
//				Logger.debug("Setting HTTP Response Content Type: application/octect-stream");
//				response.setHeader("Content-Disposition",
//	                    "attachment; filename=\"" + zipFileName+ ".zip\"");
//				response.setContentType("application/octect-stream");
//				File file = (File) obj;
//				FileInputStream fis = new FileInputStream(file);
//				try (ReadableByteChannel inputChannel = Channels.newChannel(fis); 
//					 WritableByteChannel outputChannel = Channels.newChannel(response.getOutputStream())) {
//					
//					ByteBuffer buffer = ByteBuffer.allocate(10240);
//					long size = 0;
//					
//					while (inputChannel.read(buffer) != -1)  {
//						buffer.flip();
//						size += outputChannel.write(buffer);
//						buffer.clear();
//					} // end while
// 					
//					response.setHeader("content-length", String.valueOf(size));
//					
//				} // end try
//			} // end if-else
			response.getWriter().flush();
			
//		} catch (ServletException e) {
//			if (e.getMessage().contains("process hasn't exited") && async.equalsIgnoreCase("true")) {
//			} else 
//				throw e;
		} catch (Exception e) {
			throw new ServletException(e);
		}	

	}
	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}

	private JSONArray packDownloadKeyIntoJSONArray(String newKey) {
		JSONArray jsonArray = new JSONArray();
		JSONObject jObject = new JSONObject();
		jObject.put(JSONUtil.JSON_KEY, newKey);
		jsonArray.add(jObject);
		
		JSONObject jsonObject = new JSONObject();
//		jsonObject.put("Messsage", "With the key above, you can check for ZIP file status. Once the files have been downloaded, you will be notified at " + email);
		jsonObject.put("Messsage", "With the key above, you can check for ZIP file status.");
		
		Logger.debug("JSON Array Compiled: " + jsonArray.toJSONString());
		 
		return jsonArray;
	}
	
	private String generateLogDownloadKey() {
		if (regexUtil == null ) regexUtil = new Generex(PropertiesManager.getApplicationProperty(W3ID_LOGS_KEY_REGEX_PROP));

		String randomStr = "";
		int len = Integer.parseInt(PropertiesManager.getApplicationProperty(W3ID_LOGS__KEY_LENGTH_PROP));
		for (int i = 0; i < len; i++) {
			randomStr += regexUtil.random();
		}
		System.out.println(randomStr);
		
		return randomStr;
	}

}
