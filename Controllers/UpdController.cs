using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using MongoDB.Bson;
using MongoDB.Driver;

namespace EmeraldSysPKIBackend.Controllers
{
    [Route("v1/upd")]
    [ApiController]
    public class UpdController : ControllerBase
    {
        private MongoClient client;

        public UpdController()
        {
            MongoClientSettings settings = MongoClientSettings.FromConnectionString(Environment.GetEnvironmentVariable("MONGODB_AUTH_STR"));
            client = new MongoClient(settings);
        }

        [HttpPatch("crl")]
        public IActionResult PatchCrl([FromQuery]string key)
        {
            // temporary
            if (key != "YKa023BXo9hf0r0ycF20gxz6D") return new JsonResult(new { Success = false, Message = "KEY_INVALID" });

            IMongoDatabase database = client.GetDatabase("main");
            IMongoCollection<BsonDocument> collection = database.GetCollection<BsonDocument>("certificateRequests");

            FilterDefinition<BsonDocument> filter1 = Builders<BsonDocument>.Filter.Eq("status", "revoked");
            FilterDefinition<BsonDocument> filter2 = Builders<BsonDocument>.Filter.Exists("revokedInfo");

            List<BsonDocument> revokedCerts = collection.Find(filter1 & filter2).ToList();

            List<UpdEntry> generated = new List<UpdEntry>();
            Dictionary<string, RSA> caKeys = new Dictionary<string, RSA>();

            IEnumerable<string> caKeyFiles = Directory.EnumerateFiles(Program.CURRENT_DIR + @"/ca", "*").Where(f => f.EndsWith(".pem"));

            foreach (string caKeyFilePath in caKeyFiles)
            {
                RSA privKey = RSA.Create();

                using (FileStream fs = System.IO.File.OpenRead(caKeyFilePath))
                {
                    StreamReader reader = new StreamReader(fs);
                    PemReader pem = new PemReader(reader);
                    var obj = pem.ReadPemObject();
                    privKey.ImportRSAPrivateKey(obj.Content, out _);
                    pem.Reader.Close();
                }

                caKeys.Add(Path.GetFileNameWithoutExtension(caKeyFilePath), privKey);
            }

            IEnumerable<string> caCertFiles = Directory.EnumerateFiles(Program.CURRENT_DIR + @"/ca", "*").Where(f => f.EndsWith(".crt"));

            foreach (string caCertFilePath in caCertFiles)
            {
                string caCertFileName = Path.GetFileNameWithoutExtension(caCertFilePath);

                if (caKeys.ContainsKey(caCertFileName))
                {
                    RSA privKey = caKeys[caCertFileName];

                    using (X509Certificate2 pub = new X509Certificate2(caCertFilePath))
                    using (X509Certificate2 cert = pub.CopyWithPrivateKey(privKey))
                    {
                        var convertedCert = DotNetUtilities.FromX509Certificate(cert);

                        // Start CRL Process
                        X509V2CrlGenerator crl = new X509V2CrlGenerator();
                        crl.SetIssuerDN(convertedCert.SubjectDN);

                        DateTime updTime = DateTime.UtcNow;
                        crl.SetThisUpdate(updTime);
                        crl.SetNextUpdate(updTime.AddDays(14));

                        Random rand = new Random();

                        crl.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(convertedCert));
                        crl.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.ValueOf(rand.Next(1, 40))));

                        SecureRandom secureRand = new SecureRandom(new CryptoApiRandomGenerator());

                        AsymmetricKeyParameter kp = DotNetUtilities.GetKeyPair(privKey).Private;
                        Asn1SignatureFactory sig = new Asn1SignatureFactory("SHA1withRSA", kp, secureRand);

                        for (int i = 0; i < revokedCerts.Count; i++)
                        {
                            BsonDocument document = revokedCerts[i];
                            if (document.Contains("type") && document["type"].IsInt32)
                            {
                                int type = document["type"].AsInt32;
                                if (Enum.IsDefined(typeof(Models.CertRequest.CertificateType), type))
                                {
                                    switch ((Models.CertRequest.CertificateType)type)
                                    {
                                        case Models.CertRequest.CertificateType.CodeSigning:
                                        {
                                            if (caCertFileName == "trustedid_code2022")
                                            {
                                                if (document.Contains("serialNumber") && document["serialNumber"].IsString)
                                                {
                                                    string serialNum = document["serialNumber"].AsString;
                                                    if (document["revokedInfo"].IsBsonDocument)
                                                    {
                                                        BsonDocument revokedInfo = document["revokedInfo"].AsBsonDocument;
                                                        if (revokedInfo.Contains("revocationDate") && revokedInfo.Contains("revocationReason") && revokedInfo["revocationDate"].IsBsonDateTime && revokedInfo["revocationReason"].IsInt32)
                                                        {
                                                            DateTime revocationDate = revokedInfo["revocationDate"].AsBsonDateTime.ToUniversalTime();
                                                            int revocationReason = revokedInfo["revocationReason"].AsInt32;
                                                            if (Enum.IsDefined(typeof(OCSPController.CRLReason), revocationReason))
                                                            {
                                                                crl.AddCrlEntry(new BigInteger(serialNum), revocationDate, revocationReason);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                        case Models.CertRequest.CertificateType.OrganizationSSL:
                                        {
                                            if (caCertFileName == "trustedid_ov2022")
                                            {
                                                if (document.Contains("serialNumber") && document["serialNumber"].IsString)
                                                {
                                                    string serialNum = document["serialNumber"].AsString;
                                                    if (document["revokedInfo"].IsBsonDocument)
                                                    {
                                                        BsonDocument revokedInfo = document["revokedInfo"].AsBsonDocument;
                                                        if (revokedInfo.Contains("revocationDate") && revokedInfo.Contains("revocationReason") && revokedInfo["revocationDate"].IsBsonDateTime && revokedInfo["revocationReason"].IsInt32)
                                                        {
                                                            DateTime revocationDate = revokedInfo["revocationDate"].AsBsonDateTime.ToUniversalTime();
                                                            int revocationReason = revokedInfo["revocationReason"].AsInt32;
                                                            if (Enum.IsDefined(typeof(OCSPController.CRLReason), revocationReason))
                                                            {
                                                                crl.AddCrlEntry(new BigInteger(serialNum), revocationDate, revocationReason);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                        case Models.CertRequest.CertificateType.TimestampInternal:
                                        {
                                            if (caCertFileName == "trustedid_ts2022")
                                            {
                                                if (document.Contains("serialNumber") && document["serialNumber"].IsString)
                                                {
                                                    string serialNum = document["serialNumber"].AsString;
                                                    if (document["revokedInfo"].IsBsonDocument)
                                                    {
                                                        BsonDocument revokedInfo = document["revokedInfo"].AsBsonDocument;
                                                        if (revokedInfo.Contains("revocationDate") && revokedInfo.Contains("revocationReason") && revokedInfo["revocationDate"].IsBsonDateTime && revokedInfo["revocationReason"].IsInt32)
                                                        {
                                                            DateTime revocationDate = revokedInfo["revocationDate"].AsBsonDateTime.ToUniversalTime();
                                                            int revocationReason = revokedInfo["revocationReason"].AsInt32;
                                                            if (Enum.IsDefined(typeof(OCSPController.CRLReason), revocationReason))
                                                            {
                                                                crl.AddCrlEntry(new BigInteger(serialNum), revocationDate, revocationReason);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                        case Models.CertRequest.CertificateType.IntermediateRoot2022:
                                        {
                                            if (caCertFileName == "trusted_id_root_2022")
                                            {
                                                if (document.Contains("serialNumber") && document["serialNumber"].IsString)
                                                {
                                                    string serialNum = document["serialNumber"].AsString;
                                                    if (document["revokedInfo"].IsBsonDocument)
                                                    {
                                                        BsonDocument revokedInfo = document["revokedInfo"].AsBsonDocument;
                                                        if (revokedInfo.Contains("revocationDate") && revokedInfo.Contains("revocationReason") && revokedInfo["revocationDate"].IsBsonDateTime && revokedInfo["revocationReason"].IsInt32)
                                                        {
                                                            DateTime revocationDate = revokedInfo["revocationDate"].AsBsonDateTime.ToUniversalTime();
                                                            int revocationReason = revokedInfo["revocationReason"].AsInt32;
                                                            if (Enum.IsDefined(typeof(OCSPController.CRLReason), revocationReason))
                                                            {
                                                                crl.AddCrlEntry(new BigInteger(serialNum), revocationDate, revocationReason);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                        default:
                                            break;
                                    }
                                }
                            }
                        }

                        X509Crl genCrl = crl.Generate(sig);
                        byte[] der = genCrl.GetEncoded();

                        generated.Add(new UpdEntry
                        {
                            CA = caCertFileName,
                            Contents = System.Text.Encoding.UTF8.GetString(der)
                        });
                    }
                }
            }

            return Ok(new { Success = true, Values = generated });
        }
    }
}
