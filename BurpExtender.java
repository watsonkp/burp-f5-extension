package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
	private static PrintWriter stdout;
	private static PrintWriter stderr;

    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        this.helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("F5 BIG-IP cookie check");
        
        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);

	// Save a way of printing
	stdout = new PrintWriter(callbacks.getStdout(), true);
	stderr = new PrintWriter(callbacks.getStderr(), true);
    }

	private InetSocketAddress getOriginServer(String s) {
		String[] segments = s.split("\\.");
		if (segments.length != 3) {
			stderr.println("ERROR: expected 3 dot separated segments");
			return null;
		}

		String ipv4Segment = "0000";
		if (!segments[2].equals(ipv4Segment)) {
			stderr.println("ERROR: IPv6 unsupported because I have never seen it");
			return null;
		}

		try {
			InetAddress addr = decodeIPv4(segments[0]);
			return new InetSocketAddress(addr, decodePort(segments[1]));
		} catch (UnknownHostException  e) {
			stderr.println(e);
			return null;
		}
	}

	private InetAddress decodeIPv4(String s) throws UnknownHostException {
		long encoded = Long.parseLong(s);
		byte first = (byte) ((encoded >> 24) & 0xff);
		byte second = (byte) ((encoded >> 16) & 0xff);
		byte third = (byte) ((encoded >> 8) & 0xff);
		byte fourth = (byte) (encoded & 0xff);
		return InetAddress.getByAddress(new byte[]{fourth, third, second, first});
	}
	private int decodePort(String s) {
		int encoded = Integer.parseInt(s);
		int lower = 0xff & encoded;
		int upper = encoded >> 8;
		return (lower << 8) | upper;
	}

    //
    // implement IScannerCheck
    //
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
	final List<ICookie> cookies = helpers.analyzeResponse(baseRequestResponse.getResponse()).getCookies();
	if (cookies.size() == 0) {
		return null;
	}

	String s = "";
	String prefix = "BIGipServer";
	InetSocketAddress addr = null;
	// TODO: handle multiple F5 cookies being set on a single response
	for (ICookie cookie : cookies) {
		if (cookie.getName().length() < prefix.length()) {
			continue;
		}
		// TODO: do a DNS lookup to check for differences, public, private
		// TODO: different severity based on public or private?
		if (!cookie.getName().substring(0, prefix.length()).equals(prefix)) {
			continue;
		}

		addr = getOriginServer(cookie.getValue());
	}

	if (addr == null) {
		return null;
	}

	List<IScanIssue> issues = new ArrayList<>(1);
	issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(),
				       helpers.analyzeRequest(baseRequestResponse).getUrl(), 
				       new IHttpRequestResponse[] { baseRequestResponse }, 
				       "F5 BIG-IP persistence cookie discloses origin server",
				       "Information",
				       addr));
	return issues;
    }

//    @Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
					     IScannerInsertionPoint insertionPoint)
	{
		return null;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		// This method is called when multiple issues are reported for the same URL 
		// path by the same extension-provided check. The value we return from this 
		// method determines how/whether Burp consolidates the multiple issues
		// to prevent duplication
		//
		// Since the issue name is sufficient to identify our issues as different,
		// if both issues have the same name, only report the existing issue
		// otherwise report both issues
		if (existingIssue.getIssueName().equals(newIssue.getIssueName()) &&
		    existingIssue.getIssueDetail().equals(newIssue.getIssueDetail())) {
			return -1;
		} else {
			return 0;
		}
	}
}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue {
	private IHttpService httpService;
	private URL url;
	private IHttpRequestResponse[] httpMessages;
	private String name;
	private String severity;
	private ArrayList<InetSocketAddress> addrs;

	public CustomScanIssue(IHttpService httpService,
			       URL url, 
			       IHttpRequestResponse[] httpMessages, 
			       String name,
			       String severity,
			       InetSocketAddress addr) {
		this.httpService = httpService;
		this.url = url;
		this.httpMessages = httpMessages;
		this.name = name;
		this.severity = severity;
		this.addrs = new ArrayList<>();
		addrs.add(addr);
	}
    
    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    public ArrayList<InetSocketAddress> getAddresses()
    {
        return addrs;
    }

	public void addAddress(InetSocketAddress addr) {
		addrs.add(addr);
	}


    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
	// TODO: prettier printing
	//for (InetSocketAddress addr : addrs) {
	return addrs.toString();
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }
    
}
