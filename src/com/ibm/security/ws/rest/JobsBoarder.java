package com.ibm.security.ws.rest;

/**
 * REST-based Servlet that boards IBM w3id Federation Partner jobs provisioned by the SSO 
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
 * Servlet implementation class JobsBoarder
 */
@WebServlet(name = "boardJobs", urlPatterns = "/boardJobs")
public class JobsBoarder extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	private Map<String, String> jobsDir;
	static IBMw3idFedSSOPartnerJobs jobsUtil;
	
	static Properties appProps;

       
    /**
     * @throws IOException 
     * @see HttpServlet#HttpServlet()
     */
    public JobsBoarder() throws IOException {
    	
    	jobsDir = new Hashtable<String, String>();
    	jobsUtil = new IBMw3idFedSSOPartnerJobs();
    	appProps = PropertiesManager.getApplicationProperties();

    }
    
    public void init(String environment) throws IOException {
    	Logger.debug("Inside method: " + this.getClass().getName() 
    			+ ".init(String environment)");

    	appProps = PropertiesManager.getApplicationProperties();
            if (environment.equalsIgnoreCase("Staging")) {
        		jobsDir.put("SAML2", "ICIO_Jobs");
        		Logger.debug("Using value " + appProps.getProperty("saml_jobs_dir_stag"));
        		jobsDir.put("OIDC", "ICIO_OIDC_Jobs");
        		Logger.debug("Using value " + appProps.getProperty("oidc_jobs_dir_stag"));
            } else if (environment.equalsIgnoreCase("Test") || environment.equalsIgnoreCase("Dev")) {
            	jobsDir.put("SAML2", "ICIO_Jobs_Dev");
        		Logger.debug("Using value " + appProps.getProperty("saml_jobs_dir_test"));
            	jobsDir.put("OIDC", "ICIO_OIDC_Jobs_Dev");
        		Logger.debug("Using value " + appProps.getProperty("oidc_jobs_dir_test"));
    		} else if (environment.equalsIgnoreCase("Prod")) {
            	jobsDir.put("SAML2", "ICIO_Jobs_Prod");
        		Logger.debug("Using value " + appProps.getProperty("saml_jobs_dir_prod"));
        		jobsDir.put("OIDC", "ICIO_OIDC_Jobs_Prod");
        		Logger.debug("Using value " + appProps.getProperty("oidc_jobs_dir_prod"));
    		}

    }
    
    public void init(String environment, String authType) throws IOException {
    	Logger.debug("Inside method: " + this.getClass().getName() 
    			+ ".init(String environment, String authType)");
    	
    	init(environment);
        
		if (authType != null && !authType.equals("")) {
			if(authType.equalsIgnoreCase("oidc")) {
				jobsDir.remove("SAML2");
				Logger.debug("Removed SAML2 because it was not specified.");
			} else if(authType.equalsIgnoreCase("saml") || authType.equalsIgnoreCase("saml2")) {
				jobsDir.remove("OIDC");
				Logger.debug("Removed OIDC because it was not specified.");
			}
			
		}
        
    }


	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
    
	@SuppressWarnings("unchecked")
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		Logger.debug("Inside Servlet (" + request.getMethod() + "): " + getServletConfig().getServletName());

		HttpServletUtil.logRequestInfo(request);
		JSONArray jsonArray = new JSONArray();

		String async = "false";
//		String async = Boolean.toString(!Boolean.parseBoolean(appProps.getProperty("async_boarding")));
		Logger.debug("async (from property file) = " + async);
		
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
			String authTypeInput = "";
			
			try {
				format = request.getParameter("fmt").toString();
			} catch (Exception ignoreit) {}
			Logger.debug("format = " + format);

			
			try {
				authTypeInput = request.getParameter("auth").toString();
			} catch (Exception ignoreit) {}
			Logger.debug("authTypeInput = " + authTypeInput);

			
			try {
				async = request.getParameter("async").toString();
			} catch (Exception ignoreit) {}
			Logger.debug("async (from override) = " + async);

			
			if (!authTypeInput.equalsIgnoreCase("oidc") 
					&& !authTypeInput.equalsIgnoreCase("saml")
					&& !authTypeInput.equalsIgnoreCase("saml2")) {
				init(env);
			} else if (authTypeInput.equalsIgnoreCase("oidc") 
					|| authTypeInput.equalsIgnoreCase("saml")
					|| authTypeInput.equalsIgnoreCase("saml2")) {
				init(env, authTypeInput);
			}

			Logger.debug("Size of Keyset: " + jobsDir.size());
			
			int counter = 0;

			JSONObject[] jsonObject = new JSONObject[jobsDir.size()];
				
			for (String authType : jobsDir.keySet()) {
				Logger.debug("authType = " + authType);
				if (authType != null) {
					authStatus = Boolean.toString(
							jobsUtil.boardJobs(
									authType.toLowerCase(), 
									env.toLowerCase(), 
									Boolean.parseBoolean(async),
									env.equalsIgnoreCase("prod")));
					jsonObject[counter] = new JSONObject();
					jsonObject[counter].put("AuthType", authType);
					jsonObject[counter].put("JobStatus", authStatus);
					jsonArray.add(jsonObject[counter]);
					Logger.debug("authType = " + authType);
					Logger.debug("authStatus = " + authStatus);
					counter++;
				}
			}
			
			Logger.debug("Setting HTTP Response Content Type: application/json");
			response.setContentType("application/json");

			Logger.debug("Setting HTTP Response Access-Control-Allow-Origin: *");
			response.setHeader("Access-Control-Allow-Origin", "*");

			response.getWriter().print(jsonArray);
			response.getWriter().flush();
			
			
		} catch (ServletException e) {
			if (e.getMessage().contains("process hasn't exited") && async.equalsIgnoreCase("true")) {
			} else throw e;
		} catch (Exception e) {
			throw new ServletException(e);
		}
		
	}

}
