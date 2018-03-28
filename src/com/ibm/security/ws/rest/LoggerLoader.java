package com.ibm.security.ws.rest;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ibm.security.util.Logger;

/**
 * Servlet implementation class PropertiesLoader
 */
@WebServlet(name = "reloadLogger", urlPatterns = { "/reloadLogger" })
public class LoggerLoader extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public LoggerLoader() {
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		try {
			Logger.reloadLogger();
			response.getWriter().append(new SimpleDateFormat("MM/dd/yyyy HH:mm:ss:SSS").format(new Date()) + 	" Reloaded logger. Current log level: " + Logger.getCurrentLogLevel());
		} catch (Exception e) {
			Logger.logToAllLevels("Caught exception: " + e.getMessage());
			response.getWriter().append("Caught exception: " + e.getMessage());
		} finally {
			response.flushBuffer();
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
