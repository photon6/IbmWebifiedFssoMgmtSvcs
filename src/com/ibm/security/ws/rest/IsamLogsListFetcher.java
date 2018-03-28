package com.ibm.security.ws.rest;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.ibm.security.infrastructure.IBMw3idFedSSOISAMManagement;
import com.ibm.security.util.HttpServletUtil;
import com.ibm.security.util.Logger;

/**
 * Servlet implementation class IsamLogsListFetcher
 */
@WebServlet(name = "getListingIsamLogs", urlPatterns = { "/getListingIsamLogs" })
public class IsamLogsListFetcher extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	private IBMw3idFedSSOISAMManagement webSealUtil;
	
    /**
     * @see HttpServlet#HttpServlet()
     */
    public IsamLogsListFetcher() {
    }

	/**
	 * 
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	@SuppressWarnings("unchecked")
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		Logger.debug("Inside Servlet (" + request.getMethod() + "): " + getServletConfig().getServletName());
		
		HttpServletUtil.logRequestInfo(request);
//		JSONArray jsonArray = new JSONArray();

		String async = "false";
//		String async = Boolean.toString(!Boolean.parseBoolean(appProps.getProperty("async_boarding")));
//		Logger.debug("async (from property file) = " + async);
		
		try {
			
			String env = request.getParameter("env").toString();
			Logger.debug("env = " + env);

			String format = "";
//			String authStatus = "";
			String host = "";
			
			try {
				format = request.getParameter("fmt").toString();
			} catch (Exception ignoreit) {}
			Logger.debug("format = " + format);

			
			try {
				host = request.getParameter("host").toString();
			} catch (Exception ignoreit) {}
			Logger.debug("host = " + host);

			
			try {
				async = request.getParameter("async").toString();
			} catch (Exception ignoreit) {}
			Logger.debug("async (from override) = " + async);

//			if (!host.equals(""))
//				webSealUtil = new IBMw3idFedSSOISAMManagement(env, host);
//			else 
				webSealUtil = new IBMw3idFedSSOISAMManagement(env);
			
			Logger.debug("Setting HTTP Response Content Type: application/json");
			response.setContentType("application/json");

			Logger.debug("Setting HTTP Response Access-Control-Allow-Origin: *");
			response.setHeader("Access-Control-Allow-Origin", "*");
			
			if (!host.equals(""))
				response.getWriter().print(webSealUtil.getLogsListing(host));
			else 
				response.getWriter().print(webSealUtil.getLogsListing());
			response.getWriter().flush();
			
			
		} catch (ServletException e) {
			if (e.getMessage().contains("process hasn't exited") && async.equalsIgnoreCase("true")) {
			} else 
				throw e;
		} catch (Exception e) {
			throw new ServletException(e);
		}
		
	}

}
