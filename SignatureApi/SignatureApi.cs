using System;
using System.Text;
using System.Linq;
using System.Security.Cryptography;


namespace SignatureApi
{
    /**
     * This class is responsible for handeling signature related functionality.
     * 
     * In order to secure the transfer of all transactions, a symmetric signature is generated on Payconiq’s servers and the 
     * merchant’s backend. Once generated on both sides, the signature is send to Payconiq to validate the transaction request.
     * Only when both sides recognize the same symmetric signature, a transaction will be considered as valid and will be processed. 
     * As we need to generate this key on both sides, secret information needs to be shared between them.
     **/
    public class SignatureApi
    {
        private byte[] sourceByte;

        /**
         * Constructor for the SignatureApi class.
         * 
         * string merchantId : Unique number used to identify merchant within Payconiq platform, acquired as part of the sign up process
         * string secretKey : Used to secure communications between merchant and Payconiq
         * string currency : Generally accepted form of money. For instance "EUR"
         * string amount : Quantity of money based on the specified currency. For instance "0.01" euro
         * string webhookId (optional): A simple event-notification id via HTTP POST
         **/
        public SignatureApi(string merchantId, string secretKey, string currency, string amount, string webhookId = "")
        {
            if(merchantId == null || merchantId.Equals("")) {

                throw new SignatureGenerationException("Merchant id is a required parameter which should be filled.");
            }
            if(secretKey == null || secretKey.Equals("")) {

                throw new SignatureGenerationException("Secret key is a required parameter which should be filled.");
            }
            if(currency == null || currency.Equals("")) {

                throw new SignatureGenerationException("Currency is a required parameter which should be filled.");
            }
            if(amount == null || amount.Equals("")) {

                throw new SignatureGenerationException("Amount is a required parameter which should be filled.");
            }
 
            string sourceData = String.Format("{0}{1}{2}{3}{4}", merchantId, webhookId, currency, amount, secretKey);
            this.sourceByte = Encoding.ASCII.GetBytes(sourceData);
        }

        /**
         * Generates the signature based on the provided info in the constructor of the class.
         * string hashAlgorithm : provided hash algorithm to generate the signature based on that. 
         * Note : Other hash algorithms can be set to be used as well.
         * 
         * return string : Generated hash signature based on merchantId, secretKey, currency, amount, webhookId
         **/
        public string GenerateSignature(string hashAlgorithm)
        {
            // create the cryptoServiceProvider instance based on the provided valid hash algorithm
            HashAlgorithm cryptoServiceProvider = null;
            if(hashAlgorithm.Equals(SignatureApiConstants.CRYPTOGRAPHIC_HASH_ALGORITHM_SHA256)) {
                cryptoServiceProvider = new SHA256CryptoServiceProvider();
            }

            // check the validity of cryptoServiceProvider instance
            if(cryptoServiceProvider == null) {
                throw new SignatureGenerationException("Provided hash algorithm is not valid or not implemented.");
            }

            // generate signature
            string signature = System.Convert.ToBase64String(cryptoServiceProvider.ComputeHash(this.sourceByte));

            // check the creation of the singnature
            if(signature == null || signature.Equals("")) 
            {
                throw new SignatureGenerationException("Signed signature is empty.");
            }

            // return the generated signature
            return signature;
               
        }

        /**
         * Verify the provided signature.
         * This function compares the provided signature with the actual data that is used to generate signatures.
         * string signatureToBeVerified : Generated hash signature based on merchantId, secretKey, currency, amount, webhookId
         * string hashAlgorithm : provided hash algorithm to verify the signature based on that. 
         * 
         * return bool: true in case of signature verification acceptance; false otherwise.
         **/ 
        public bool verifySignature(string signatureToBeVerified, string hashAlgorithm)
        {
            string sourceSignature = this.GenerateSignature(hashAlgorithm);
            if(sourceSignature.Equals(signatureToBeVerified)) {
                return true;
            }
            return false;
        }
    }
}
