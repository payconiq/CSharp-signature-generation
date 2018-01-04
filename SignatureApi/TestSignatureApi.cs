using System;
using System.Text;

namespace SignatureApi
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            String merchantId = "123";
            String secretKey = "SecretKey";
            String currency = "EUR";
            String amount = "1000";
            String webhookId = null;

            // Create instance of the signature api
            SignatureApi signatureApi = new SignatureApi(merchantId, secretKey, currency, amount, webhookId);

            // Signature creation 
            string signature = signatureApi.GenerateSignature(SignatureApiConstants.CRYPTOGRAPHIC_HASH_ALGORITHM_SHA256);
            Console.WriteLine(signature);

            // Verify the generated signature
            bool signatureVerified = signatureApi.verifySignature(signature, SignatureApiConstants.CRYPTOGRAPHIC_HASH_ALGORITHM_SHA256);
            Console.WriteLine("Signature is verified? " + signatureVerified);

            // Verify the incorrect signature
            string incorrectSignature = "MTIzRVVSMTAwMFNlY3JldEtleQ11";
            Console.WriteLine("Signature is verified? " + signatureApi.verifySignature(incorrectSignature, SignatureApiConstants.CRYPTOGRAPHIC_HASH_ALGORITHM_SHA256));      
        }
    }
}
