@isTest
public class AWSQConnectorTest {

    @isTest
    static void testGetSearchedTextSuccess() {
        // Set up a mock HTTP response for the AWSQInterface callout
        Test.setMock(HttpCalloutMock.class, new AWSQConnectorMock());

        // Prepare test input for the InvocableMethod
        AWSQConnector.FlowInput input = new AWSQConnector.FlowInput();
        input.searchText = 'Sample search text';
        input.customMetadataName = 'TestMetadata';
        
        List<AWSQConnector.FlowInput> inputs = new List<AWSQConnector.FlowInput>{ input };
        
        // Execute the method
        List<String> result = AWSQConnector.getSearchedText(inputs);
        
        // Verify the result
        System.assertNotEquals(0, result.size(), 'Expected non-empty result');
        System.assert(result[0].contains('systemMessage'), 'Response should contain systemMessage text');
        System.assert(result[0].contains('Citations'), 'Response should contain Citations');
    }

    @isTest
    static void testGetSearchedTextNoMetadata() {
        // Prepare test input with an incorrect custom metadata name
        AWSQConnector.FlowInput input = new AWSQConnector.FlowInput();
        input.searchText = 'Sample search text';
        input.customMetadataName = 'NonExistentMetadata';
        
        List<AWSQConnector.FlowInput> inputs = new List<AWSQConnector.FlowInput>{ input };
        
        // Execute the method and verify the response
        List<String> result = AWSQConnector.getSearchedText(inputs);
        
        System.assertEquals(1, result.size(), 'Expected single response in result');
        System.assertEquals('No Metadata Configuration Found', result[0], 'Expected metadata not found message');
    }

    // Mock HTTP response for successful call
    private class AWSQConnectorMock implements HttpCalloutMock {
        public HTTPResponse respond(HTTPRequest req) {
            HttpResponse res = new HttpResponse();
            res.setStatusCode(200);
            res.setBody('{"systemMessage":"Sample response","sourceAttributions":[{"url":"https://example.com"}]}');
            return res;
        }
    }
}