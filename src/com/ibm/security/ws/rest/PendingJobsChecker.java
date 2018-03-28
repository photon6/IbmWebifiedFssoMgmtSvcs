package com.ibm.security.ws.rest;

/**
 * REST-based Servlet that detects IBM w3id Federation Partner jobs provisioned by the SSO 
 * Self-Service Provisioner utility.
 * 
 * @author rkhanna@us.ibm.com
 * 
 * Change history:
 * --------------------------------------------------------------------------------------------------
 * | VERSION	| DATE			|	CHANGE DESCRIPTION												|
 * --------------------------------------------------------------------------------------------------
 * | 0.1		| 12/06/2016	|	Initial version with Staging and Dev jobs detection and boarding|
 * --------------------------------------------------------------------------------------------------
 * | 0.2		| 12/09/2016	|	Supporting simulated production jobs detection and boarding		|
 * --------------------------------------------------------------------------------------------------
 * | 1.0		| 12/16/2016	|	Supporting production jobs detection and boarding; baselined	|
 * |			|				|	release.														|
 * --------------------------------------------------------------------------------------------------
 */

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import com.ibm.security.sso.federation.IBMw3idFedSSOPartnerJobs;
import com.ibm.security.util.HttpServletUtil;
import com.ibm.security.util.Logger;
import com.ibm.security.util.PropertiesManager;

/**
 * Servlet implementation class IBMw3idFedSSOPartnerJobsServlet
 */
@WebServlet(name = "checkPendingJobs", urlPatterns = "/checkPendingJobs")
public class PendingJobsChecker extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	boolean debug;
	private Map<String, String> jobsDir;
	
	private static IBMw3idFedSSOPartnerJobs jobsUtil;
	private static Properties appProps;
	
    /**
     * @throws NoSuchAlgorithmException 
     * @throws IOException 
     * @see HttpServlet#HttpServlet()
     */
    public PendingJobsChecker() throws NoSuchAlgorithmException, IOException {
    	Logger.debug("Inside constructor: " + this.getClass().getName()
    			+ "()");

    	jobsDir = new Hashtable<String, String>();
    	jobsUtil = new IBMw3idFedSSOPartnerJobs();
    	appProps = PropertiesManager.getApplicationProperties();
    	
    	Logger.debug("Size of application properties: " + appProps.keySet().size());
    	
    }
    
    public void init(String environment) {
    	Logger.debug("Inside method: " + this.getClass().getName()
    			+ "init(String environment)");
    	
    	Logger.debug("environment: " + environment);
        if (environment.equals("Staging") || environment.equals("Stag")) {
    		jobsDir.put("SAML2", "ICIO_Jobs");
    		jobsDir.put("OIDC", "ICIO_OIDC_Jobs");
        } else if (environment.equals("Test") || environment.equals("Dev")) {
        	jobsDir.put("SAML2", "ICIO_Jobs_Dev");
        	jobsDir.put("OIDC", "ICIO_OIDC_Jobs_Dev");
		} else if (environment.equals("Prod")) {
        	jobsDir.put("SAML2", "ICIO_Jobs_Prod");
    		jobsDir.put("OIDC", "ICIO_OIDC_Jobs_Prod");
		} 
        
    }
    
	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	@SuppressWarnings({ "unchecked" })
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		Logger.debug("Inside Servlet (" + request.getMethod() + "): " + getServletConfig().getServletName());
		
		HttpServletUtil.logRequestInfo(request);

		JSONArray jsonArray = new JSONArray();
		
		try {			
			
			String env = "";
			try {
				env = request.getParameter("env").toString();
			} catch (Exception e) {
				throw new ServletException("Environment is required: Please supply one of the following: 'env=prod' or 'env=staging' or 'env=test'");
			}
			Logger.debug("env = " + env);

			String format = "";
			String authStatus = ""; 
				
			try {
				format = request.getParameter("fmt").toString();
			} catch (Exception ignoreit) {}
			
			Logger.debug("Format: " + format);
			
			init(env);
			
			Logger.debug("Size of Keyset: " + jobsDir.size());		
			
			int counter = 0;

			JSONObject[] jsonObject = new JSONObject[jobsDir.size()];
			
			for (String authType : jobsDir.keySet()) {
				Logger.debug("authType = " + authType);
				if (authType != null) {
					authStatus = Boolean.toString(
							jobsUtil.checkForPendingJobs(
									authType.toLowerCase(), 
									env.toLowerCase(), 
									env.equalsIgnoreCase("prod")));
					Logger.debug("Building JSON Array");
					jsonObject[counter] = new JSONObject();
					jsonObject[counter].put("AuthType", authType);
					jsonObject[counter].put("JobStatus", authStatus);
					jsonArray.add(jsonObject[counter]);
					Logger.debug("Added 'authType' value of '" + authType + "' to JSON Arrray");
					Logger.debug("Added 'authStatus' value of '" + authStatus + "' to JSON Arrray");
					counter++;
				}
			} // end for				

			Logger.debug("Setting HTTP Response Content Type: application/json");
			response.setContentType("application/json");

			Logger.debug("Setting HTTP Response Access-Control-Allow-Origin: *");
			response.setHeader("Access-Control-Allow-Origin", "*");

			response.getWriter().print(jsonArray);
			response.getWriter().flush();
			
		} catch (Exception e) {
			throw new ServletException(e);
		}
				
	}
	

}
