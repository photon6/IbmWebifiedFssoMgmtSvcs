package com.ibm.security.ws.rest;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.InputMismatchException;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.ibm.security.infrastructure.IBMw3idFedSSOISAMManagement;
import com.ibm.security.util.HttpServletUtil;
import com.ibm.security.util.JSONUtil;
import com.ibm.security.util.Logger;
import com.ibm.security.util.PropertiesManager;
import com.mifmif.common.regex.Generex;


/**
 * Servlet implementation class IsamLogsFetcher
 */
@WebServlet(name = "getInfraLogs", urlPatterns = { "/getInfraLogs" })
public class IsamLogsFetcher extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	private IBMw3idFedSSOISAMManagement webSealUtil;
	private Properties appProps;
       
	private static final String W3ID_LOGS_KEY_REGEX_PROP="W3ID_LOGS_KEY_REGEX";
	private static final String W3ID_LOGS__KEY_LENGTH_PROP="W3ID_LOGS__KEY_LENGTH";
	
	private static Generex regexUtil;


    /**
     * @see HttpServlet#HttpServlet()
     * 
     */
    public IsamLogsFetcher() {
    }
    
    private void initializeProps() throws IOException {
    	appProps = PropertiesManager.getApplicationProperties();
    }

	/**
	 * 
	 * REST service is overloaded in the following way with respect to retrieving webSEAL log files:
	 * 
	 * In addition to 'env', for which "dev" or "prod" or "staging" are accceptable values...
	 * 
	 * 1) ...if the following are present, the GET function is to start logs fetching
	 *    - 'logs' is comma-separated listing of webSEAL log files to fetch
	 *    - 'host' is comma-separated listing of webSEAL hosts form which to fetch logs
	 *    - 'filter' is either "all", "latest" or "specified" (default is "latest")
	 *    - 'search' is an enclosed string (enclosed with "double quotes") with only "specified" filter
	 *    			 (note that if no filter is supplied with this key word, "specified" would assume today's files)
	 * 
	 * 2) ...if the following are present, the GET function is to fetch the downloaded log files
	 *     - 'key' is the key associated with the set of log files being fetched
	 * 
	 * In any case, the following are also acceptable input parameters:
	 * 
	 * - 'fmt' with either "json" or "xml" for response format ("json" is the default)
	 * - 'async' with either true or false for asynchronous reply ("true" is the default)
	 * 
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		Logger.debug("Inside Servlet (" + request.getMethod() + "): " + getServletConfig().getServletName());
		
		if (appProps == null) initializeProps();
		if (regexUtil  == null) regexUtil = new Generex(PropertiesManager.getApplicationProperty(W3ID_LOGS_KEY_REGEX_PROP));
		
		HttpServletUtil.logRequestInfo(request);

		String async = "true";
//		String async = Boolean.toString(!Boolean.parseBoolean(appProps.getProperty("async_boarding")));
//		Logger.debug("async (from property file) = " + async);
		
		try {
			
			String env = "";
			try {
				env = request.getParameter("env").toString();
			} catch (Exception e) {
				throw new ServletException("Environment is required: Please supply one of the following: 'env=prod' or 'env=staging' or 'env=test'");
			}
			Logger.debug("env = " + env);

			String format = "";
			try {
				format = request.getParameter("fmt").toString();
			} catch (Exception ignoreit) {}
			Logger.debug("format = " + format);

			
			
			webSealUtil = new IBMw3idFedSSOISAMManagement(env);
			
			Logger.debug("Setting HTTP Response Access-Control-Allow-Origin: *");
			response.setHeader("Access-Control-Allow-Origin", "*");
			
			Object obj = null;
			
			String newKey = generateLogDownloadKey();
			String email = request.getHeader("IV-USER");

			
			String downloadedLogsKey = "";
			try {
				downloadedLogsKey = request.getParameter("key").toString();
			} catch (Exception ignoreit) {}
			Logger.debug("downloadedLogsKey = " + downloadedLogsKey);
			
			// if a download key is specified, then assume it's a request to download log files
			if (!downloadedLogsKey.equals("")) {

				Logger.debug("Requested to retreive downloaded files with the key: " + downloadedLogsKey);
				obj = webSealUtil.getLogs(downloadedLogsKey, env); // get those downloaded files, or check status
				
			} else {
				
				String host = "", logsInput = "", searchFor="";
				String logsFilter = "latest";
				String timeframe = "", fromDate = "", toDate = "";
				String[] logs = new String[0];
				String[] hosts = new String[0];

				try {
					host = request.getParameter("host").toString();
					hosts = PropertiesManager.parseProps(host, ",");
				} catch (Exception ignoreit) {}
				Logger.debug("host = " + host);
	
				
				try {
					async = request.getParameter("async").toString();
				} catch (Exception ignoreit) {}
				Logger.debug("async (from override) = " + async);
	
				try {
					logsInput = request.getParameter("logs").toString();
					logs  = PropertiesManager.parseProps(logsInput, ",");
				} catch (Exception ignoreit) {}
				Logger.debug("logs to fetch = " + logsInput);
				
				if (logs.length > 0) {
					for (int i = 0; i < logs.length; i++) {
						Logger.debug("log " + (i+1) + " to fetch: " + logs[i]);	
					} // end for
				} // end if
				
				try {
					logsFilter = request.getParameter("filter").toString();
				} catch (Exception ignoreit) {}
				Logger.debug("logsFilter = " + logsFilter);

				try {
					searchFor = request.getParameter("search").toString();
					searchFor = searchFor.substring(1, searchFor.length()-1);
					
					if (!logsFilter.equals("specified")) logsFilter = "specified";
				} catch (Exception ignoreit) {}
				Logger.debug("searching for = " + searchFor);

				String[] dates = null;
				try {
					timeframe = request.getParameter("timeframe").toString();
					dates = parseDates(timeframe, "-");
				} catch (Exception doSomethingElse) {
					if (!searchFor.equals("")) {
						dates = getTodaysDate();
					}
				} finally {
				}
				
				try {
					fromDate = dates[0];
					toDate = dates[1];
					dates = null;
					if (timeframe.equals("")) {
						timeframe = fromDate + "-" + toDate;
					}
				} catch (Exception ignoreit) {
				}
				Logger.debug("timeframe = " + timeframe);
				Logger.debug("fromDate = " + fromDate);
				Logger.debug("toDate = " + toDate);
				
				if (hosts.length > 1) { // more than one host is specified
					
					HashSet<String> keySet = new HashSet<String>();
					
					
					for (int i = 0; i < hosts.length; i++) {
						Logger.debug("Requested to initiate files download from host: " + hosts[i]);
//						keySet.add(!timeframe.equals("")
//							?(!searchFor.equals(""))
//								?webSealUtil.searchLogs(hosts[i], logs, fromDate, toDate, newKey, email, searchFor, !Boolean.parseBoolean(async)) // search downloaded files
//								:webSealUtil.getLogs(hosts[i], logs, fromDate, toDate, newKey, email, !Boolean.parseBoolean(async)) // downlaod time-based files
//							:webSealUtil.getLogs(hosts[i], logs, logsFilter, newKey, email, !Boolean.parseBoolean(async))); // download files
						
						
						obj = (!timeframe.equals("")
								?(!searchFor.equals(""))
									?webSealUtil.searchLogs(hosts[i], logs, fromDate, toDate, newKey, email, searchFor, !Boolean.parseBoolean(async), true) // search downloaded files
									:webSealUtil.getLogs(hosts[i], logs, fromDate, toDate, newKey, email, !Boolean.parseBoolean(async), true) // downlaod time-based files
								:webSealUtil.getLogs(hosts[i], logs, logsFilter, newKey, email, !Boolean.parseBoolean(async), true)); // download files
						
					}
//					Logger.debug("Keys: " + keySet.toString());
//					String[] keys = new String[keySet.size()];
//					keySet.toArray(keys);
//					Logger.debug("Keys in String[]: " + Arrays.toString(keys));
//					obj = keys;
					
				} else if (!host.equals("")) { // assuming one host is specified
					Logger.debug("Requested to initiate files download from host: " + host);
					obj = !timeframe.equals("")
							?(!searchFor.equals(""))
									?webSealUtil.searchLogs(host, logs, fromDate, toDate, newKey, email, searchFor, !Boolean.parseBoolean(async), true) // search downloaded files
									:webSealUtil.getLogs(host, logs, fromDate, toDate, newKey, email, !Boolean.parseBoolean(async), true) // downlaod time-based files
							:webSealUtil.getLogs(host, logs, logsFilter, newKey, email, !Boolean.parseBoolean(async), true); // download files
									
				} else { // from all hosts 
					Logger.debug("Requested to initiate files download from all hosts");
					obj = !timeframe.equals("")
							?(!searchFor.equals(""))
									?webSealUtil.searchLogs(logs, fromDate, toDate, newKey, email, searchFor, !Boolean.parseBoolean(async)) // search downloaded files
									:webSealUtil.getLogs(logs, fromDate, toDate, newKey, request.getHeader("IV-USER"), !Boolean.parseBoolean(async)) // downlaod time-based files
							:webSealUtil.getLogs(logs, logsFilter, newKey, request.getHeader("IV-USER"), !Boolean.parseBoolean(async)); // download files 
				} // end if (hosts.length > 0)
				
				
			} // end if (!downloadedLogsKey.equals(""))
			
			if (obj instanceof JSONArray) { // should not be getting this now anyway
				Logger.debug("obj is instance of JSONArray");
				Logger.debug("Setting HTTP Response Content Type: application/json");
				response.setContentType("application/json");
				response.getWriter().print((JSONArray) obj);
			} else if (obj instanceof String) {
				Logger.debug("obj is instance of String");
				Logger.debug("Setting HTTP Response Content Type: application/json");
				response.setContentType("application/json");
				response.getWriter().print((JSONArray) packDownloadKeyIntoJSONArray(new String[] {(String) obj}));
			} else if (obj instanceof String[]) {
				Logger.debug("obj is instance of String[]");
				JSONArray jsonArray = new JSONArray();
				String[] keys = (String[]) obj;
				Logger.debug("Preparing to pack these keys into JSON Format: " + Arrays.toString(keys));
//				for (String key : keys) {
//					Logger.debug("key: " + key);
				jsonArray = packDownloadKeyIntoJSONArray(keys);
//				}
				Logger.debug("Setting HTTP Response Content Type: application/json");
				response.setContentType("application/json");
				response.getWriter().print(jsonArray);
			} else if (obj instanceof File) {
				Logger.debug("obj is instance of File");
				Logger.debug("Setting HTTP Response Content Type: application/octect-stream");
				response.setHeader("Content-Disposition",
	                    "attachment; filename=\"" + downloadedLogsKey+ ".zip\"");
				response.setContentType("application/octect-stream");
				File file = (File) obj;
				FileInputStream fis = new FileInputStream(file);
				try (ReadableByteChannel inputChannel = Channels.newChannel(fis); 
					 WritableByteChannel outputChannel = Channels.newChannel(response.getOutputStream())) {
					
					ByteBuffer buffer = ByteBuffer.allocate(10240);
					long size = 0;
					
					while (inputChannel.read(buffer) != -1)  {
						buffer.flip();
						size += outputChannel.write(buffer);
						buffer.clear();
					} // end while
 					
					response.setHeader("content-length", String.valueOf(size));
					
				} // end try
			} // end if-else
					
			response.getWriter().flush();
			
		} catch (ServletException e) {
			if (e.getMessage().contains("process hasn't exited") && async.equalsIgnoreCase("true")) {
			} else 
				throw e;
		} catch (Exception e) {
			throw new ServletException(e);
		}	
		
	}

/*
	
	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
	
		Logger.debug("Inside Servlet (" + request.getMethod() + "): " + getServletConfig().getServletName());
		
		if (appProps == null) initializeProps();
		
		HttpServletUtil.logRequestInfo(request);

		String async = "true";
//		String async = Boolean.toString(!Boolean.parseBoolean(appProps.getProperty("async_boarding")));
//		Logger.debug("async (from property file) = " + async);
		
		try {
			
			String env = request.getParameter("env").toString();
			Logger.debug("env = " + env);

//			String format = "";
//			String downloadedLogsKey = "";
			String host = "";
			String logsInput = "";
//			String logsFilter = "latest";
			String[] logs = new String[0];
			String[] hosts = new String[0];
			
//			try {
//				format = request.getParameter("fmt").toString();
//			} catch (Exception ignoreit) {}
//			Logger.debug("format = " + format);
//
//
//			try {
//				logsFilter = request.getParameter("filter").toString();
//			} catch (Exception ignoreit) {}
//			Logger.debug("logsFilter = " + logsFilter);
//			
//			
//			try {
//				downloadedLogsKey = request.getParameter("key").toString();
//			} catch (Exception ignoreit) {}
//			Logger.debug("downloadedLogsKey = " + downloadedLogsKey);
//			
//			// if no key is specified, then assume it's a request to download log files
//			if (downloadedLogsKey.equals("") || downloadedLogsKey == null) {
			
				try {
					host = request.getParameter("host").toString();
					hosts = PropertiesManager.parseProps(host, PropertiesManager.getApplicationProperty("ISAM_WEBSEAL_LOGS_DELIMITER"));
				} catch (Exception ignoreit) {}
				Logger.debug("host = " + host);
	
				
//				try {
//					async = request.getParameter("async").toString();
//				} catch (Exception ignoreit) {}
//				Logger.debug("async (from override) = " + async);
	
				try {
					logsInput = request.getParameter("logs").toString();
					logs  = PropertiesManager.parseProps(logsInput, ",");
				} catch (Exception ignoreit) {}
				Logger.debug("logs to fetch = " + logsInput);
				
				if (logs.length > 0) {
					for (int i = 0; i < logs.length; i++) {
						Logger.debug("log " + (i+1) + " to fetch: " + logs[i]);	
					} // end for
				} // end if
				
//			} // end if (downloadedLogsKey.equals(""))
				
			webSealUtil = new IBMw3idFedSSOISAMManagement(env);
			
			Logger.debug("Setting HTTP Response Access-Control-Allow-Origin: *");
			response.setHeader("Access-Control-Allow-Origin", "*");
			
			Object obj = (Object) webSealUtil.getLogs(host, logs, "specified", request.getSession().getId(), request.getHeader("IV-USER"), !Boolean.parseBoolean(async)); // download files
//			Object obj = null;
//			
//			if (hosts.length > 0) {
//				obj = downloadedLogsKey.equals("") // if no key specified
//						?webSealUtil.getLogs(hosts, logs, logsFilter, request.getSession().getId(), !Boolean.parseBoolean(async)) // download files 
//						:webSealUtil.getLogs(downloadedLogsKey); // get those downloaded files, or check status
//			} else {
//				obj = downloadedLogsKey.equals("") // if no key specified
//						?webSealUtil.getLogs(logs, logsFilter, request.getSession().getId(), !Boolean.parseBoolean(async)) // download files 
//						:webSealUtil.getLogs(downloadedLogsKey); // get those downloaded files, or check status
//			} // end if (hosts.length > 0)
			
			if (obj instanceof JSONArray) {
				Logger.debug("Setting HTTP Response Content Type: application/json");
				response.setContentType("application/json");
				response.getWriter().print((JSONArray) obj);
//			} else if (obj instanceof File) {
//				Logger.debug("Setting HTTP Response Content Type: application/octect-stream");
//				response.setHeader("Content-Disposition",
//	                    "attachment; filename=\"" + downloadedLogsKey+ ".zip\"");
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
			} // end if-else
			
					
			response.getWriter().flush();
			
		} catch (ServletException e) {
			if (e.getMessage().contains("process hasn't exited") && async.equalsIgnoreCase("true")) {
			} else 
				throw e;
		} catch (Exception e) {
			throw new ServletException(e);
		}	
		
	}

*/
	
	private String[] parseDates(String timeframe, String delimeter) throws InputMismatchException, ParseException {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".parseDates(String timeframe, String delimeter)");
		
		StringTokenizer st = new StringTokenizer(timeframe, delimeter);
		Logger.debug("There are " + st.countTokens() + " dates to parse");
		String dates[] = new String[st.countTokens()];
		
		try {
			for (int i = 0; i < dates.length & st.hasMoreTokens(); i++) {
				String token = st.nextToken();
				Logger.debug("Token parsed: " + token);
				Date dateTest = new SimpleDateFormat(PropertiesManager.getApplicationProperty("TIMEFRAME_PATTERN_INPUT")).parse(token);
				dates[i] = new SimpleDateFormat(PropertiesManager.getApplicationProperty("TIMEFRAME_PATTERN_FILECHECK")).format(dateTest);
				dateTest = null;
				
			}
		} catch (InputMismatchException e) {
			e.printStackTrace();
			Logger.logToAllLevels("Caught exceptions: " + e.getMessage());
			throw e;
		} catch (ParseException e) {
			e.printStackTrace();
			Logger.logToAllLevels("Caught exceptions: " + e.getMessage());
			throw e;
		}
			
		return dates;
	}
	
	private String[] getTodaysDate() throws InputMismatchException, ParseException {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getTodaysDate()");
		
		String todaysDate = new SimpleDateFormat(PropertiesManager.getApplicationProperty("TIMEFRAME_PATTERN_FILECHECK")).format(new Date());
		
		String dates[] = new String[] {
				todaysDate, todaysDate
		};

		return dates;
	}
	

	
	@SuppressWarnings("unchecked")
	private JSONArray packDownloadKeyIntoJSONArray(String[] keys) {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".packDownloadKeyIntoJSONArray(String newKey)");
		JSONArray jsonArray = new JSONArray();
		for (String key : keys) {
			JSONObject jObject = new JSONObject();
			jObject.put(JSONUtil.JSON_KEY, key);
			Logger.debug("jObject in String: " + jObject.toJSONString());
			jsonArray.add(jObject);
			Logger.debug("jsonArray in String: " + jsonArray.toJSONString());			
		}
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("Messsage", "With the key above, you can check for ZIP file status.");
		
		Logger.debug("JSON Array Compiled: " + jsonArray.toJSONString());
		 
		return jsonArray;
	}

	private String generateLogDownloadKey() {
		
		String randomStr = "";
		int len = Integer.parseInt(PropertiesManager.getApplicationProperty(W3ID_LOGS__KEY_LENGTH_PROP));
		for (int i = 0; i < len; i++) {
			randomStr += regexUtil.random();
		}
		System.out.println(randomStr);
		
		return randomStr;
	}
	

	
}
