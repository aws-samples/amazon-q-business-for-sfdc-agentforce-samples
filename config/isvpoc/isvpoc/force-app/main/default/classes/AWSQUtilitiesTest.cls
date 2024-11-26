@isTest
public class AWSQUtilitiesTest {

    @isTest
    static void testGetSearchedTextSuccess() {
        // Set up a mock HTTP response for the AWSQInterface callout
        Test.setMock(HttpCalloutMock.class, new AWSQUtilitiesMock());

        // Retrieve the custom metadata record
        awsapn__AWS_Q_Connector_Details__mdt metadata = [SELECT awsapn__endpoint__c, awsapn__HTTP_Method__c, Timeout__c, awsapn__Headers__c FROM awsapn__AWS_Q_Connector_Details__mdt LIMIT 1];
        
        // Execute the method
        String requestText = 'Sample search text';
        List<String> result = AWSQUtilities.getSearchedText(requestText, metadata);
        
        // Verify the result
        System.assertNotEquals(0, result.size(), 'Expected non-empty result');
        System.assert(result[0].contains('systemMessage'), 'Response should contain systemMessage text');
        System.assert(result[0].contains('Citations'), 'Response should contain Citations');
    }

    @isTest
    static void testGetSearchedTextFailure() {
        // Set up a mock HTTP response for a failed request
        Test.setMock(HttpCalloutMock.class, new AWSQUtilitiesFailureMock());

        // Retrieve the custom metadata record
        awsapn__AWS_Q_Connector_Details__mdt metadata = [SELECT awsapn__endpoint__c, awsapn__HTTP_Method__c, Timeout__c, awsapn__Headers__c FROM awsapn__AWS_Q_Connector_Details__mdt LIMIT 1];
        
        // Execute the method and verify the exception
        String requestText = 'Sample search text';
        try {
            AWSQUtilities.getSearchedText(requestText, metadata);
            System.assert(false, 'Expected a CalloutException to be thrown');
        } catch (CalloutException e) {
            System.assert(e.getMessage().contains('Failed to initiate'), 'Exception message should contain "Failed to initiate"');
        }
    }
    
    // Mock HTTP response for successful call
    private class AWSQUtilitiesMock implements HttpCalloutMock {
        public HTTPResponse respond(HTTPRequest req) {
            HttpResponse res = new HttpResponse();
            res.setStatusCode(200);
            res.setBody('{"systemMessage":"Sample response","sourceAttributions":[{"url":"https://example.com"}]}');
            return res;
        }
    }
    
    // Mock HTTP response for failed call
    private class AWSQUtilitiesFailureMock implements HttpCalloutMock {
        public HTTPResponse respond(HTTPRequest req) {
            HttpResponse res = new HttpResponse();
            res.setStatusCode(400);
            res.setBody('{"error":"Bad Request"}');
            return res;
        }
    }
}