package burp;

import java.net.*;
import java.io.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import au.com.bytecode.opencsv.*;
import org.apache.commons.io.filefilter.*;
import flex.messaging.util.FileUtils;

// my utility classes
class urlobj {
	int hashid;
	String host, path, paramname, paramvalue, paramtype;
}

class annotobj {
	String file;
	int node;
	String ipparam;
	HashSet<String> domain;
	HashSet<String> type;
}

class setupfile {
	File afile;
	FileWriter afw;
	BufferedWriter outurls;

	setupfile(String filename) {
		try {
			afile = new File(filename);
			afw = new FileWriter(afile);
			outurls = new BufferedWriter(afw);
		} catch (IOException e) {
			System.out.println("Problem creating output file");
			e.printStackTrace();
		}
	}

	void closefile() {
		try {
			outurls.close();
			afw.close();
			outurls.close();
		} catch (IOException e) {
			System.out.println("Problem closing output file");
			e.printStackTrace();
		}
	}
}

public class BurpExtender {
	public URL url_spider;
	public Date last_request;
	public Vector<IHttpRequestResponse> spi_queue = new Vector<IHttpRequestResponse>();
	public int delay = 30;
	public boolean ismonitor = false;
	ArrayList<String[]> urldatabase = new ArrayList<String[]>(); // to store
																	// limited
																	// request-response
																	// data
	Map<String, String[]> paramlist = new HashMap<String, String[]>(); // to
																		// store
																		// parameter
																		// data
	Map<String, IHttpRequestResponse> requestlist = new HashMap<String, IHttpRequestResponse>();
	Map<String, annotobj> iparamlist = new HashMap<String, annotobj>();
	IBurpExtenderCallbacks univ_callbacks;
	BufferedWriter saveurls;
	File wfile;
	FileWriter fw;

	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		univ_callbacks = callbacks;
		callbacks.setProxyInterceptionEnabled(false);
		try {
			// callbacks.excludeFromScope(new URL("any:any:any"));
			callbacks.includeInScope(new URL("http://localhost"));
			callbacks
					.includeInScope(new URL("http://zero.webappsecurity.com/"));
		} catch (MalformedURLException e) {
			System.out.println("Bad URL");
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println("Error while Burp Configuration");
			e.printStackTrace();
		}
		callbacks
				.registerMenuItem("HiphopCrawler", new CustomMenuItem(callbacks));
	}

	// Processing Request-Response Sets.
	public void processHttpMessage(String toolName, boolean messageIsRequest,
			IHttpRequestResponse messageInfo) {
		// Processing Responses from the Spider
		if (toolName == "spider") {
			if (messageIsRequest) {
				// Update last request time
				last_request = new Date();
			}
			// Save URLS that are not 404 (Not Found)
			else {
				// Start the monitor_map
				if (!ismonitor) {
					ismonitor = true;
					monitor_map();
				}
				try {
					if (messageInfo.getStatusCode() != 404) {
						try {
							spi_queue.add(messageInfo);
						} catch (Exception e) {
							System.out.println("Error adding to queue");
							e.printStackTrace();
						}
					}
				} catch (Exception e) {
					System.out
							.println("Error in getting statuscode for message"
									+ e.getMessage());
				}
			}
		} else if (toolName == "repeater" && !messageIsRequest)
			try {
				// to follow redirects to depth 5
				//check if already in the sitemap
				String target = null;
				univ_callbacks.sendToSpider(messageInfo.getUrl());
				String[] httpHeaders = univ_callbacks.getHeaders(messageInfo.getResponse());
				if (httpHeaders[0].contains("302")) {
					for (String token : httpHeaders) {
						if (token.contains("Location: "))
							target = token.substring(10);
					}
					if (target != null) {
						byte[] request = messageInfo.getRequest();
						// regex for strings- \\s(.*?)$
						String request_string = new String(request);
						String regex = "(GET /.*?)(?:(?![\n ]).)*";
						Pattern pattern = Pattern.compile(regex,
								Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
						Matcher matcher = pattern.matcher(request_string);
						if (matcher.find()) {
							request_string = matcher.replaceFirst("Get /"
									+ target);
						}
						//System.out.println("Request: " + request_string);
						request = request_string.getBytes();
						byte[] fuzzresponse = univ_callbacks.makeHttpRequest(
								messageInfo.getHost(), messageInfo.getPort(),
								false, request);
						String response_string = new String(fuzzresponse);
						//System.out.println("Redirect Response: " + response_string);
					}
				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				System.out.println("Error sending new URL to spider");
				e.printStackTrace();
			}
		// Spidering done.
		return;
	}

	// Mapping the URLs and parameters after spidering complete
	public void monitor_map() {
		// waiting for spider to finish
		try {
			Date currentTime = new Date();
			univ_callbacks.issueAlert("Monitor thread started at "
					+ currentTime + " and waiting for spider to complete.");
			// Continue waiting for after 30 secs after the last request
			while (last_request.getTime() + (delay * 100) > currentTime
					.getTime()) {
				currentTime = new Date();
				Thread.currentThread();
				Thread.yield();
				Thread.currentThread();
				Thread.sleep(delay * 1000);

			}
			univ_callbacks.issueAlert("Spidering complete at " + last_request
					+ ", constructing list.");
			messageparser();

		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			System.out.println("Error in threading etc.");
			e.printStackTrace();
		}
	}

	public void messageparser() {
		// Construction of array by parsing queue of request-responses
		while (spi_queue.size() != 0) {
			Iterator<IHttpRequestResponse> iterator = spi_queue.iterator();
			urlobj thisurl = new urlobj(); // this temporarily stores the
											// strings
			while (iterator.hasNext()) {
				IHttpRequestResponse thismessage = iterator.next();
				try {
					for (String[] s : univ_callbacks.getParameters(thismessage
							.getRequest())) {
						thisurl.host = thismessage.getHost().toString();
						thisurl.path = thismessage.getUrl().getPath()
								.toString();
						thisurl.hashid = thismessage.getUrl().hashCode();
						int i = 1;
						for (String t : s) {
							switch (i) {
							case 1:
								thisurl.paramname = t.toString();
								i++;
								break;
							case 2:
								thisurl.paramvalue = t.toString();
								i++;
								break;
							case 3:
								thisurl.paramtype = t.toString();
								break;
							default:
								break;
							}
						}

						String values[] = { null, null };
						if (paramlist.get(thisurl.paramname) != null)
							values = paramlist.get(thisurl.paramname);
						if (values[1] == null
								|| compareTo(thisurl.paramvalue, values[1]) > 0) {
							values[1] = thisurl.paramvalue.toString();
							requestlist.put(thisurl.paramname, thismessage);
						}
						if (values[0] == null
								|| compareTo(thisurl.paramvalue, values[0]) < 0) {
							requestlist.put(thisurl.paramname, thismessage);
							values[0] = thisurl.paramvalue.toString();
						}
						paramlist.put(thisurl.paramname, values);
					}
					iterator.remove();

				} catch (Exception e) {
					// TODO Auto-generated catch block
					System.out.println("Error in parsing data to arraylist");
					e.printStackTrace();
				}
			}
		}
		// Construction of array over

		// writing the data to file
		DateFormat df = new SimpleDateFormat("yyyy-MM-dd_hh-mm-ss");
		df.setTimeZone(TimeZone.getTimeZone("EST"));
		String filename = "params" + df.format(new Date());

		setupfile outputs = new setupfile(filename);
		System.out.println("Writing to file " + filename);

		Set set = paramlist.entrySet();
		Iterator i = set.iterator();
		while (i.hasNext()) {
			Map.Entry me = (Map.Entry) i.next();
			String key = me.getKey().toString();
			String[] val = paramlist.get(key);
			IHttpRequestResponse message = requestlist.get(key);
			try {
				outputs.outurls.write(key + ", " + val[0] + ", " + val[1]
						+ ", " + message.getUrl().toString() + "\n");
			} catch (IOException e) {
				System.out.println("Error writing paramlist;");
				e.printStackTrace();
			} catch (Exception e) {
				System.out.println("Error parsing IHttprequestresponse");
				e.printStackTrace();
			}
		}
		System.out.println("File Ready");
		outputs.closefile();
		// Writing to file over
		makerequests();
	}

	public void makerequests() {
		// read files from HipHop
		FilenameFilter filter = new FilenameFilter() {
		    public boolean accept(File dir, String name) {
		        return name.endsWith("_annotations.txt");
		    }
		};
		File folder = new File("./input/");
		File[] listoffiles= folder.listFiles(filter);

		for(int i = 0; i < listoffiles.length; i++) {
		    // do something with the file
		    String fileName= listoffiles[i].toString();
		    
		//String fileName = "/home/osiris/workspace/burp4/input/Function php$__$__$php$test$action_php_annotations.txt";
		CSVReader reader;
		List<String[]> annotations = new ArrayList<String[]>();
		try {
			reader = new CSVReader(new FileReader(fileName));
			annotations = reader.readAll();
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			System.out.println("Error reading file from hiphop");
			e1.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("Error reading file from hiphop");
			e.printStackTrace();
		}
		for (String[] items : annotations) {
			int count = 0;
			annotobj newannot = new annotobj();
			String regex = "[-+.^:,']";
			String replacement = "";
			HashSet<String> annot_domain = new HashSet<String>();
			HashSet<String> annot_type = new HashSet<String>();
			for (String token : items) {
				switch (count) {
				case 0:
					newannot.file = token;
					count++;
					break;
				case 1:
					newannot.node = Integer.parseInt(token);
					count++;
					break;
				case 2:
					newannot.ipparam = token.replaceAll(regex, replacement);
					count++;
					break;
				default:
					if (token.contains("D:") && token.length() > 2) {
						annot_domain.add(token.substring(2).replaceAll(regex,
								replacement));
					} else if (token.contains("T:") && token.length() > 2) {
						annot_type.add(token.substring(2).replaceAll(regex,
								replacement));
					}
					break;
				}
				//System.out.println(token);
			}
			newannot.domain = annot_domain;
			newannot.type = annot_type;
			iparamlist.put(newannot.ipparam, newannot);
		}
	}
		// reading from hiphop file done.

		// Generate parameter value for parameter name
		Set set = paramlist.entrySet();
		Iterator i = set.iterator();
		while (i.hasNext()) {
			Map.Entry me = (Map.Entry) i.next();
			String pname = me.getKey().toString();
			if (iparamlist.get(pname) != null) {
				annotobj tempannot = iparamlist.get(pname);
				IHttpRequestResponse fuzzedmessage = requestlist.get(pname);
				for (String param : tempannot.domain) {
					try {
						byte[] request = fuzzedmessage.getRequest();
						// regex for strings- \\s(.*?)$
						String request_string = new String(request);
						String regex = "(" + pname + "="
								+ ".*?)(?:(?![&;\n ]).)*";
						Pattern pattern = Pattern.compile(regex,
								Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
						Matcher matcher = pattern.matcher(request_string);
						if (matcher.find()) {
							request_string = matcher.replaceFirst(pname + "="
									+ param);
						} else {
							continue;
						}
						System.out.println("New Request: " + request_string);
						request = request_string.getBytes();

						// fuzzedmessage.setRequest(request);
						byte[] fuzzresponse = univ_callbacks.makeHttpRequest(
								fuzzedmessage.getHost(),
								fuzzedmessage.getPort(), false, request);
						// System.out.println(new String(fuzzresponse));
						String response_string = new String(fuzzresponse);
						// if(fuzzresponse!=null){
						//System.out.println("Response: " + response_string);
						// IHttpRequestResponse newmessage = null;
						// newmessage.setRequest(request);
						// newmessage.setResponse(fuzzresponse);
						// univ_callbacks.sendToSpider(newmessage.getUrl());
						// }
					} catch (Exception e) {
						System.out
								.println("Error setting fuzzed param to message : "
										+ e.getMessage());
					}
				}
			}
		}
	}

	// Controlled Closing
	public void applicationClosing() {
		try {
			System.out.println("Bye");
		} catch (Exception e) {
			System.out.println("Something may have gone wrong while exiting "
					+ e.getMessage());
		}
		return;
	}

	// defining what the HiphopCrawler menu does
	class CustomMenuItem implements IMenuItemHandler {
		IBurpExtenderCallbacks mcallbacks;
		public URL url;

		public CustomMenuItem(IBurpExtenderCallbacks callbacks) {
			mcallbacks = callbacks;
			// set the monitor=false so that a new file can be created on every
			// invocation of the plugin
			ismonitor = false;
		}

		public void menuItemClicked(String menuItemCaption,
				IHttpRequestResponse[] messageInfo) {
			try {
				System.out
						.println("Starting My Burp Extension to Crawl better V4");
				System.out.println("Spidering these URLs");
				for (int i = 0; i < messageInfo.length; i++) {
					System.out.println("Host: " + messageInfo[i].getHost());
					url = messageInfo[i].getUrl();
					System.out.println("URL: " + url);
					mcallbacks.sendToSpider(url);
				}
			} catch (Exception e) {
				System.out.println("Error in Menu Handling");
				e.printStackTrace();
			}
		}
	}

	// my own comparison function- compares numeric, alphanumeric and alphabetic
	public int compareTo(String paramvalue, String string) {
		int result = 0;
		Double val1 = 0.0, val2 = 0.0;
		// if a and b are strings
		result = paramvalue.compareTo(string);
		// if a and b are numeric
		if (paramvalue.matches("[-+]?\\d+(\\.\\d+)?")
				&& string.matches("[-+]?\\d+(\\.\\d+)?")) {
			try {
				val1 = Double.parseDouble(paramvalue);
				val2 = Double.parseDouble(string);
			} catch (NumberFormatException e) {
				System.out.println("Error in Parsing Integers");
			}
			if (val1 > val2)
				result = 1;
			else
				result = -1;
		}
		return result;
	}
}
