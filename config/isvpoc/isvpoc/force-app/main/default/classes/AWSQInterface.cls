/**
 * @description Interface class to invoke the API.
 * @author AWS
 * @date 2024-11-22
 */
public class AWSQInterface {
	
    /**
     * @description Builds the HTTP request object and invokes the HTTPS endpoint.
     * @param requestWrapper
     * **/
    public static HTTPResponse doCall(AWSQInterface.requestObj requestWrapper){
        HttpRequest req = new HttpRequest();
        req.setEndpoint( requestWrapper.endpoint );
        req.setTimeout( requestWrapper.timeout );
        req.setMethod(requestWrapper.httpMethod);
        req.setBody(requestWrapper.body);
        if(requestWrapper.headerMap != null){
         	for(String headerVal: requestWrapper.headerMap.keyset()){
            	req.setHeader(headerVal,requestWrapper.headerMap.get(headerVal));
        	}	   
        }
        Http http = new Http();
        HTTPResponse res = http.send(req);
        return res;
    }
    
    /**
     * @description Wrapper class containing all attributes required for callout.
     * @author AWS
     * @date 2024-11-22
     */
    public class requestObj{
        public string endpoint;
        public string httpMethod;
        public string body;
        public integer timeout;
        public Map<String,String> headerMap;
    }
}