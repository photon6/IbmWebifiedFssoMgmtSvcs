package com.ibm.security.ws.rest;

import java.io.IOException;
import java.util.Arrays;
import java.util.StringTokenizer;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ibm.security.infrastructure.IBMw3idFedSSOOIDCManagement;
import com.ibm.security.util.HttpServletUtil;
import com.ibm.security.util.Logger;

/**
 * Servlet implementation class OidcTokenManager
 */
@WebServlet(
		name = "deletetokens", 
		urlPatterns = { 
				"/deletetokens", 
				"/querytokens", 
				"/oidctokens", 
				"/counttokens"
		})
public class OidcTokenManager extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	private IBMw3idFedSSOOIDCManagement oidcUtil; 
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public OidcTokenManager() {
        oidcUtil = new IBMw3idFedSSOOIDCManagement();
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		if (oidcUtil == null) oidcUtil = new IBMw3idFedSSOOIDCManagement();
		
		HttpServletUtil.logRequestInfo(request);
		String env = "";
		String action = "";
		String userId = "";
		String[] userIds = new String[1];
		
		try {
			env = request.getParameter("env").toString().toUpperCase();
		} catch (Exception e) {
			Logger.debug("env parameter is missing in request");
			String errorMsg = "An environment must be specified. Please specifiy one of the following:\n";
			errorMsg += "\tenv=prod\n";
			errorMsg += "\tenv=staging\n";
			errorMsg += "\tenv=test\n";
			throw new ServletException(errorMsg);
		}

		
		if (request.getServletPath().toLowerCase().contains("oidctokens")) {
			try {
				action = request.getParameter("action").toString().toLowerCase();
			} catch (Exception e) {
				Logger.debug("action parameter is missing in request");
				String errorMsg = "An action must be specified. Please specifiy one of the following:\n";
				errorMsg += "\taction=delete\n";
				errorMsg += "\taction=count\n";
				errorMsg += "\taction=query\n";
				throw new ServletException(errorMsg);
			}
		}

		
		
		try {
			userId = request.getParameter("userid").toString().toLowerCase();
		} catch (Exception e) {
			Logger.debug("userId parameter is missing in request");
			String errorMsg = "At least one user ID is required; comma-separete more than one user ID\n";
			throw new ServletException(errorMsg);
		}
		
		if (userId.contains(",")) {
			StringTokenizer st = new StringTokenizer(userId, ",");
			userIds = new String[st.countTokens()];
			for (int i = 0; st.hasMoreTokens(); i++) {
				userIds[i] = st.nextToken();
			}
		} else {
			userIds[0] = userId;
		}
		
		if (request.getServletPath().toLowerCase().contains("query") || action.equals("query")) {
			response.getWriter().append(queryTokens(userIds, env));
		} else if (request.getServletPath().toLowerCase().contains("count") || action.equals("count")) {
			response.getWriter().append(countTokens(userIds, env));
		} else if (request.getServletPath().toLowerCase().contains("delete") || action.equals("delete")) {
			response.getWriter().append(deleteTokens(userIds, env));
		} else {
			response.getWriter().append("");
		}
		
		response.getWriter().flush();
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);

	}
	
	/**
	 * @see HttpServlet#doDelete(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		if (request.getServletPath().toLowerCase().contains("oidctokens")) {
			response.getWriter().append("\nYou are requesting to DELETE OIDC Tokens").append(request.getContextPath());
		}
	}
	
	private String queryTokens(String[] userIds, String env) {
		return ("You are requesting to QUERY OIDC Tokens for " + Arrays.toString(userIds) + " from " + env);
	}
	
	private String countTokens(String[] userIds, String env) {
		return ("You are requesting to COUNT OIDC Tokens for " + Arrays.toString(userIds) + " from " + env);
	}

	private String deleteTokens(String[] userIds, String env) throws IOException {
		oidcUtil.removeOidcTokens(userIds, env);
		return ("Request to DELETE OIDC Tokens for " + Arrays.toString(userIds) + " from " + env + " has been noted.");
	}


}
