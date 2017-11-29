

package burp;

import java.util.Base64;


public class BurpExtender implements IBurpExtender {

    private IExtensionHelpers helpers;
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        //Name of the extension
        callbacks.setExtensionName ("Burp64");
        
        //Grabbing the helper functions
        helpers = callbacks.getHelpers();
        
        // register ourselves as an Intruder payload processor
        callbacks.registerIntruderPayloadProcessor(new Burp64Processor("Url_Safe Base64 Encoder",true));
        callbacks.registerIntruderPayloadProcessor(new Burp64Processor("Url_Safe Base64 Decoder",false));
        
        
    }
    
   
    
    public class Burp64Processor implements IIntruderPayloadProcessor {
    
    public String name;
    public boolean encode;
    
    Burp64Processor(String name, boolean encode){
        this.name = name;
        this.encode = encode;
    }
    

    public String getProcessorName() {
        return this.name;
    }

    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        //Base64.getUrlDecoder()
        byte[] output;

        if(encode){
            output = Base64.getUrlEncoder().encode(currentPayload);
        }else{
            String input = helpers.bytesToString(helpers.urlDecode(currentPayload));
            try{
                output = Base64.getUrlDecoder().decode(input);
            }catch(IllegalArgumentException e){
                System.out.println("Error decoding urlsafe_base64. Are you sure it is urlsafe base64?");
                output = null;
            }
        }

        return output;
    }
    
}
    
    
}//end of top class
