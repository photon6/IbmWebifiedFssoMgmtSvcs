package com.ibm.security.ws.rest;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ibm.security.infrastructure.IBMw3idFedSSOPartnerJobsInfo;
import com.ibm.security.sso.federation.IBMw3idFedSSOPartnerJobs;
import com.ibm.security.util.HttpServletUtil;
import com.ibm.security.util.Logger;

/**
 * Servlet implementation class ParnerBoardingInfo
 */
@WebServlet(
		name = "getPartnerBoardingInfo", 
		urlPatterns = { 
				"/getPartnerBoardingInfo"
		})

public class ParnerBoardingInfo extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	private static IBMw3idFedSSOPartnerJobsInfo jobsUtil;

       
    /**
     * @throws IOException 
     * @see HttpServlet#HttpServlet()
     */
    public ParnerBoardingInfo() throws IOException {
    	initialize();
    }
    
    private void initialize() throws IOException {
    	jobsUtil = new IBMw3idFedSSOPartnerJobsInfo();
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		Logger.debug("Inside Servlet (" + request.getMethod() + "): " + getServletConfig().getServletName());
		
		HttpServletUtil.logRequestInfo(request);

//		JSONArray jsonArray = new JSONArray();
		
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
			String infoLevel = "INFO";
				
			try {
				format = request.getParameter("fmt").toString();
			} catch (Exception ignoreit) {}
			
			Logger.debug("Format: " + format);
			
			try {
				infoLevel = request.getParameter("level").toString();
			} catch (Exception ignoreit) {}
			
			Logger.debug("Info Requested: " + infoLevel);
			
			String info = jobsUtil.getPartnerJobInfo(env, infoLevel, format);
			
			Logger.debug("Setting HTTP Response Content Type: text");
			response.setContentType("text");
			
			Logger.debug("Setting HTTP Response Access-Control-Allow-Origin: *");
			response.setHeader("Access-Control-Allow-Origin", "*");

			response.getWriter().print(info);
			response.getWriter().flush();
			
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

}
