using System;
namespace SignatureApi
{
    /**
     * Class to specify the exceptions which can occure during signature generation or verification
     **/
    public class SignatureGenerationException: Exception 
    {
        public SignatureGenerationException(String message): base(message)
        {}
    }
}
