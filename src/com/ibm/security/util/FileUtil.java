package com.ibm.security.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.InputMismatchException;
import java.util.Scanner;


public class FileUtil {
	
	public static boolean replaceInFile(String filepath, String searchString, String replaceString) throws IOException {
    	Logger.debug("Inside method: " + FileUtil.class.getName() 
    			+ ".writeToFile(String file, String fileContents)");

    	return false;
	}
	
	public static boolean writeToFile(String filepath, String fileContents, boolean overwrite) throws IOException {
    	Logger.debug("Inside method: " + FileUtil.class.getName() 
    			+ ".writeToFile(String file, String fileContents)");
		
    	Logger.debug("The following content will be written to " + filepath);
    	Logger.debug(System.lineSeparator() + fileContents);
		File f = new File(filepath);
		
		File fDir = new File(f.getParent());
		
		if (!fDir.isDirectory()) {
			Logger.debug(fDir.getAbsolutePath() + " does not exist, so creating it now");
			fDir.mkdirs();
			fDir = null;
		}
			
		
		FileWriter fw = new FileWriter(f, !overwrite);
		boolean success = true;
		
		try {
			fw.write(fileContents);
			fw.flush();
		} catch (IOException e) {
			Logger.debug("Exception caught: " + e.getMessage());
			throw e;
		} catch (Exception e) {
			success = false;
		} finally {
			fw.close();
		}
		
<<<<<<< HEAD
		Logger.debug("Contents were written " + (success?"successfully":"unsuccessfully") + " to the file: " + file);
=======
		Logger.debug("Contents were written " + (success?"successfully":"unsuccessfully") + " to the file: " + filepath);
>>>>>>> logs-download
		
		return success;
	}
	
	@SuppressWarnings("unused")
	private static String readFile(String filepath) throws FileNotFoundException {
		
		return readFile(new File(filepath));
		
	}
	private static String readFile(File file) throws FileNotFoundException {
    	Logger.debug("Inside method: " + FileUtil.class.getName() 
    			+ ".String readFile(File file)");
		
		StringBuilder sb = new StringBuilder();
		
		Scanner fileScanner = new Scanner(file);
		while (fileScanner.hasNextLine()) {
			sb.append(fileScanner.nextLine());
			if (fileScanner.hasNextLine()) sb.append("\r\n");
		}
			
		fileScanner.close();
		
		return sb.toString();
	}
	
	public static ArrayList<String> loadFileLinesToArrayList(File file, ArrayList<String> list) throws FileNotFoundException {
    	Logger.debug("Inside method: " + FileUtil.class.getName() 
    			+ ".loadFileLinesToArrayList(File file, ArrayList<String> list)");
    	
    	Logger.debug("File to load from: " + file.getAbsolutePath());
		
		Scanner scanner = new Scanner(file);
		while (scanner.hasNextLine()) {
			list.add(scanner.nextLine());
		}
		
		Logger.debug("Number of lines loaded  from file \"" + file.getAbsolutePath() + "\": " + list.size());
		
		return list;
	}

	@SuppressWarnings("resource")
	public static ArrayList<String> loadFileLinesToArrayList(File file, String filter, boolean filterOut, ArrayList<String> list) throws FileNotFoundException {
		Scanner scanner = new Scanner(file);
		while (scanner.hasNextLine()) {
			String line = scanner.nextLine();
			if ((!filterOut)?line.contains(filter):!line.contains(filter)) list.add(line);
		}
		
		return list;
	}

	public static boolean isContentInFile(String filepath, String searchString) throws FileNotFoundException {
    	Logger.debug("Inside method: " + FileUtil.class.getName() 
    			+ ".isContentInFile(String file, String fileContents)");
		
		File f = new File(filepath);
		
		boolean matchFound = false;
		
		

		if (f.exists()) {
			String fileContents = readFile(f);
			
			Logger.debug("Searching " + filepath + " for matching string: " + searchString);
			matchFound = fileContents.contains(searchString);
			
		}	
		
		Logger.debug("Match result: " + matchFound);
		return matchFound;
	}
	
	public static String[] grepFile(String filepath, String searchString) throws FileNotFoundException {
    	Logger.debug("Inside method: " + FileUtil.class.getName() 
    			+ ".grepFile(String file, String searchString)");
		
		File f = new File(filepath);
		
		String matchedLine[] = new String[0];
		
		ArrayList<String> matchedLines = new ArrayList<String>(); 
		

		if (f.exists()) {

			Logger.debug("Searching " + filepath + " for matching string: " + searchString);
			Scanner fileScanner = new Scanner(f);
			while (fileScanner.hasNextLine()) {
				String line = fileScanner.nextLine();
//				Logger.debug("Evaluating line: " + line);
				if (line.contains(searchString)) {
					Logger.debug("Matched line found: " + line);
					matchedLines.add(line);
				}
			}
			
			fileScanner.close();
			
		}	
		
//		Logger.debug("Matched line: " + matchedLine);
		
		if (!matchedLines.isEmpty()) {
			matchedLine = new String[matchedLine.length];
			matchedLines.toArray(matchedLine);
		}
		
		
		return matchedLine;
	}
	
	public static boolean removeFile(String filepath) throws ParseException, InputMismatchException, FileNotFoundException {
		
		File f = new File(filepath);
		Logger.debug(f.getAbsolutePath() + " will be deleted");
		
		try {
			f.delete();
		} catch (Exception ignore) {}
		
		return (!f.exists());
		
	}
	
	public static boolean touchFile(String filepath) throws IOException {
		boolean fileTouched = false;
		File mfFile = new File(filepath);
		if (!mfFile.exists()) {
			fileTouched = mfFile.createNewFile(); 
			if (!fileTouched) Logger.logToAllLevels("Cannot touch " + filepath);;
		}

		return fileTouched;
	}


}
