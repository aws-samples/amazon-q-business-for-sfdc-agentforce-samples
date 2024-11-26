/**
 * @description AWS Utility class to build the request and parse response from AWS Q.
 * @author AWS
 * @date 2024-11-22
 */
public class AWSQUtilities {
    
    /**
     * @description executes the api interface for the search text and parses the response.
     * @param requestText
     * @param metadata
     * **/
    public static List<String> getSearchedText(String requestText,awsapn__AWS_Q_Connector_Details__mdt metadata){
        AWSQInterface.requestObj request = new AWSQInterface.requestObj();
        request.endpoint = metadata.awsapn__endpoint__c ;
        request.httpMethod = metadata.awsapn__HTTP_Method__c ;
        request.body = '{"user_id":"' + UserInfo.getUserEmail() +'","user_message":"'+requestText+ '"}';
        request.timeout = Integer.valueOf(metadata.Timeout__c);
        request.headerMap = new Map<String,String>();
        for(String headerVal: metadata.awsapn__Headers__c.split(',')){
            List<String> headerSet = headerVal.split(':');
            request.headerMap.put(headerSet[0]??'Content-type',headerSet[1]??'application/json'); 
        }

        HTTPResponse res = AWSQInterface.doCall(request);
        List<String> output = new List<String>();
        // Handle response for success or failure
        if (res != null && res.getStatusCode() == 200) {
            Map<String, Object> resMap = (Map<String, Object>) JSON.deserializeUntyped(res.getBody());
			String citations = '\n\nCitations : \n\n';
            for(Object citationObj: (List<Object>)resMap.get('sourceAttributions')){
                Map<String,Object> citationMap = (Map<String,Object>)citationObj;
                citations += (String)citationMap.get('url') + '\n';
                //citations += '&lt;a href="' + (String)citationMap.get('url') + '"&gt;test&lt;/a&gt' +  '\n';
            }
            output.add((String) resMap.get('systemMessage') + citations);  // Return the prompt response
        } else {
            throw new CalloutException('Failed to initiate : ' + 
                                       (res != null ? res.getStatus() : 'No response') + 
                                       ' - ' + (res != null ? res.getBody() : 'No body'));
        } 
        return output;
    }
}