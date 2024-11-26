/**
 * @description Apex connector class from Agentforce Apex Action to Q Interface.
 * @author AWS
 * @date 2024-11-22
 */
public class AWSQConnector {
	
    /**
     * @description Invoked by AF Action, builds the data required for the HTTPS object.
     * @param input
     * **/
    @InvocableMethod(label='QBiz API' description='Invoke this API if user requests for action from AWS Q business')
    public static List<String> getSearchedText(List<flowInput> input){
        List<String> output = new List<String>();
        //The API details to invoke is stored inside the metadata.
        awsapn__AWS_Q_Connector_Details__mdt metadata = null;
        try{
         metadata = [SELECT DeveloperName ,awsapn__endpoint__c,awsapn__Headers__c,awsapn__HTTP_Method__c,awsapn__Timeout__c 
                                                         FROM awsapn__AWS_Q_Connector_Details__mdt WHERE DeveloperName =: input[0].customMetadataName];   
        }catch(Exception ex){
            output.add('No Metadata Configuration Found');
            return output;
        }
        return AWSQUtilities.getSearchedText(input[0].searchText,metadata);
    }
    
    /**
     * @description Wrapper class holds the invocable variables.
     * @author AWS
     * @date 2024-11-22
     */
    public class FlowInput{
        @InvocableVariable(required=true description='the search text')
        public String searchText;
        @InvocableVariable(required=true description='Custom metadata name')
        public String customMetadataName;
    }
}