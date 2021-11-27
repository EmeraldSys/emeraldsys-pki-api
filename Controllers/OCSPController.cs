using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.IO.Pem;
using MongoDB.Bson;
using MongoDB.Driver;

namespace EmeraldSysPKIBackend.Controllers
{
    [Route("v1/ocsp")]
    [ApiController]
    public class OCSPController : ControllerBase
    {
        private MongoClient client;

        public OCSPController()
        {
            MongoClientSettings settings = MongoClientSettings.FromConnectionString(Environment.GetEnvironmentVariable("MONGODB_AUTH_STR"));
            client = new MongoClient(settings);
        }

        public enum CRLReason
        {
            Unspecified,
            KeyCompromise,
            CACompromise,
            AffiliationChanged,
            Superseded,
            CessationOfOperation,
            CertificateHold,
            RemoveFromCRL = 8,
            PrivilegeWithdrawn,
            AACompromise
        }

        // Todo: Automatically get the type of certificate in the request and get the issuer and validate it, only will work for one certificate
        public byte[] AutoGenerateOCSPResponse(OcspReq ocspRequest)
        {
            IMongoDatabase database = client.GetDatabase("main");
            IMongoCollection<BsonDocument> collection = database.GetCollection<BsonDocument>("certificateRequests");

            Org.BouncyCastle.X509.X509Certificate cert = null;
            RSA certPrivKey = null;

            Req[] reqList = ocspRequest.GetRequestList();

            if (reqList.Length > 0)
            {
                Req req = reqList[0];
                CertificateID cId = req.GetCertID();

                // Find serial number in collection
                BsonDocument result = collection.Find(new BsonDocument { { "serialNumber", cId.SerialNumber.ToString() } }).FirstOrDefault();

                if (result != null)
                {
                    if (result.Contains("type") && result["type"].IsInt32)
                    {
                        int type = result["type"].AsInt32;
                        if (Enum.IsDefined(typeof(Models.CertRequest.CertificateType), type))
                        {
                            switch ((Models.CertRequest.CertificateType)type)
                            {
                                case Models.CertRequest.CertificateType.CodeSigning:
                                {
                                    cert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trustedid_code2022.crt"));
                                    certPrivKey = RSA.Create();

                                    using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trustedid_code2022.pem"))
                                    {
                                        StreamReader reader1 = new StreamReader(fs);
                                        PemReader pem1 = new PemReader(reader1);
                                        var obj = pem1.ReadPemObject();
                                        certPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                                        pem1.Reader.Close();
                                    }

                                    break;
                                }
                                case Models.CertRequest.CertificateType.TimestampInternal:
                                {
                                    cert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trustedid_ts2022.crt"));
                                    certPrivKey = RSA.Create();

                                    using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trustedid_ts2022.pem"))
                                    {
                                        StreamReader reader1 = new StreamReader(fs);
                                        PemReader pem1 = new PemReader(reader1);
                                        var obj = pem1.ReadPemObject();
                                        certPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                                        pem1.Reader.Close();
                                    }

                                    break;
                                }
                                case Models.CertRequest.CertificateType.IntermediateRoot2022:
                                {
                                    cert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trusted_id_root_2022.crt"));
                                    certPrivKey = RSA.Create();

                                    using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trusted_id_root_2022.pem"))
                                    {
                                        StreamReader reader1 = new StreamReader(fs);
                                        PemReader pem1 = new PemReader(reader1);
                                        var obj = pem1.ReadPemObject();
                                        certPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                                        pem1.Reader.Close();
                                    }

                                    break;
                                }
                                case Models.CertRequest.CertificateType.DomainSSL:
                                {
                                    cert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trustedid_dv2022.crt"));
                                    certPrivKey = RSA.Create();

                                    using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trustedid_dv2022.pem"))
                                    {
                                        StreamReader reader1 = new StreamReader(fs);
                                        PemReader pem1 = new PemReader(reader1);
                                        var obj = pem1.ReadPemObject();
                                        certPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                                        pem1.Reader.Close();
                                    }

                                    break;
                                }
                                case Models.CertRequest.CertificateType.OrganizationSSL:
                                {
                                    cert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trustedid_ov2022.crt"));
                                    certPrivKey = RSA.Create();

                                    using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trustedid_ov2022.pem"))
                                    {
                                        StreamReader reader1 = new StreamReader(fs);
                                        PemReader pem1 = new PemReader(reader1);
                                        var obj = pem1.ReadPemObject();
                                        certPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                                        pem1.Reader.Close();
                                    }

                                    break;
                                }
                                case Models.CertRequest.CertificateType.EVSSL:
                                {
                                    cert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trustedid_ev2022.crt"));
                                    certPrivKey = RSA.Create();

                                    using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trustedid_ev2022.pem"))
                                    {
                                        StreamReader reader1 = new StreamReader(fs);
                                        PemReader pem1 = new PemReader(reader1);
                                        var obj = pem1.ReadPemObject();
                                        certPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                                        pem1.Reader.Close();
                                    }

                                    break;
                                }
                                case Models.CertRequest.CertificateType.EVSSL2:
                                {
                                    cert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trustedid_ev2_2022.crt"));
                                    certPrivKey = RSA.Create();

                                    using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trustedid_ev2_2022.pem"))
                                    {
                                        StreamReader reader1 = new StreamReader(fs);
                                        PemReader pem1 = new PemReader(reader1);
                                        var obj = pem1.ReadPemObject();
                                        certPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                                        pem1.Reader.Close();
                                    }

                                    break;
                                }
                                default:
                                    break;
                            }
                        }
                        else
                        {
                            return new OCSPRespGenerator().Generate(OcspRespStatus.InternalError, null).GetEncoded();
                        }

                        if (cert != null && certPrivKey != null)
                        {
                            BasicOcspRespGenerator respGen = new BasicOcspRespGenerator(cert.GetPublicKey());
                            DateTime thisUpdate = DateTime.UtcNow;

                            //var nonceExt = ocspRequest.RequestExtensions.GetExtension(OcspObjectIdentifiers.PkixOcspNonce);
                            //if (nonceExt != null) respGen.SetResponseExtensions(new X509Extensions(new[] { OcspObjectIdentifiers.PkixOcspNonce }, new[] { nonceExt }));

                            if (result.Contains("status") && result["status"].IsString)
                            {
                                if (result["status"].AsString == "revoked")
                                {
                                    if (result.Contains("revokedInfo") && result["revokedInfo"].IsBsonDocument)
                                    {
                                        BsonDocument revokedInfo = result["revokedInfo"].AsBsonDocument;
                                        if (revokedInfo.Contains("revocationDate") && revokedInfo.Contains("revocationReason"))
                                        {
                                            BsonValue rawRevocationDate = revokedInfo["revocationDate"];
                                            BsonValue rawRevocationReason = revokedInfo["revocationReason"];

                                            if (rawRevocationDate.IsBsonDateTime && rawRevocationReason.IsInt32)
                                            {
                                                DateTime revocationDate = rawRevocationDate.AsBsonDateTime.ToUniversalTime();
                                                int revocationReason = rawRevocationReason.AsInt32;

                                                if (Enum.IsDefined(typeof(CRLReason), revocationReason))
                                                {
                                                    respGen.AddResponse(cId, new RevokedStatus(revocationDate, revocationReason), thisUpdate, thisUpdate.AddDays(14), null);
                                                }
                                                else
                                                {
                                                    respGen.AddResponse(cId, new UnknownStatus(), thisUpdate, thisUpdate.AddDays(14), null);
                                                }
                                            }
                                            else
                                            {
                                                respGen.AddResponse(cId, new UnknownStatus(), thisUpdate, thisUpdate.AddDays(14), null);
                                            }
                                        }
                                        else
                                        {
                                            respGen.AddResponse(cId, new UnknownStatus(), thisUpdate, thisUpdate.AddDays(14), null);
                                        }
                                    }
                                    else
                                    {
                                        respGen.AddResponse(cId, new UnknownStatus(), thisUpdate, thisUpdate.AddDays(14), null);
                                    }
                                }
                                else if (result["status"].AsString == "good")
                                {
                                    respGen.AddResponse(cId, CertificateStatus.Good, thisUpdate, thisUpdate.AddDays(14), null);
                                }
                            }
                            else
                            {
                                respGen.AddResponse(cId, new UnknownStatus(), thisUpdate, thisUpdate.AddDays(14), null);
                            }

                            SecureRandom rand = new SecureRandom(new CryptoApiRandomGenerator());
                            Asn1SignatureFactory sig = new Asn1SignatureFactory("SHA256withRSA", DotNetUtilities.GetKeyPair(certPrivKey).Private, rand);
                            BasicOcspResp resp = respGen.Generate(sig, new Org.BouncyCastle.X509.X509Certificate[] { }, thisUpdate);
                            return new OCSPRespGenerator().Generate(OcspRespStatus.Successful, resp).GetEncoded();
                        }
                        else
                        {
                            return new OCSPRespGenerator().Generate(OcspRespStatus.InternalError, null).GetEncoded();
                        }
                    }
                    else
                    {
                        return new OCSPRespGenerator().Generate(OcspRespStatus.InternalError, null).GetEncoded();
                    }
                }
                else
                {
                    return new OCSPRespGenerator().Generate(OcspRespStatus.Unauthorized, null).GetEncoded();
                }
            }

            return new OCSPRespGenerator().Generate(OcspRespStatus.MalformedRequest, null).GetEncoded();
        }

        public byte[] GenerateOCSPResponse(OcspReq ocspRequest, Models.CertRequest.CertificateType type)
        {
            IMongoDatabase database = client.GetDatabase("main");
            IMongoCollection<BsonDocument> collection = database.GetCollection<BsonDocument>("certificateRequests");

            Org.BouncyCastle.X509.X509Certificate cert = null;
            RSA certPrivKey = null;

            if (type == Models.CertRequest.CertificateType.CodeSigning)
            {
                cert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trustedid_code2022.crt"));
                certPrivKey = RSA.Create();

                using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trustedid_code2022.pem"))
                {
                    StreamReader reader1 = new StreamReader(fs);
                    PemReader pem1 = new PemReader(reader1);
                    var obj = pem1.ReadPemObject();
                    certPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                    pem1.Reader.Close();
                }
            }
            else if (type == Models.CertRequest.CertificateType.OrganizationSSL)
            {
                cert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trustedid_ov2022.crt"));
                certPrivKey = RSA.Create();

                using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trustedid_ov2022.pem"))
                {
                    StreamReader reader1 = new StreamReader(fs);
                    PemReader pem1 = new PemReader(reader1);
                    var obj = pem1.ReadPemObject();
                    certPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                    pem1.Reader.Close();
                }
            }
            else if (type == Models.CertRequest.CertificateType.TimestampInternal)
            {
                cert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trustedid_ts2022.crt"));
                certPrivKey = RSA.Create();

                using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trustedid_ts2022.pem"))
                {
                    StreamReader reader1 = new StreamReader(fs);
                    PemReader pem1 = new PemReader(reader1);
                    var obj = pem1.ReadPemObject();
                    certPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                    pem1.Reader.Close();
                }
            }
            else if (type == Models.CertRequest.CertificateType.IntermediateRoot2022)
            {
                cert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trusted_id_root_2022.crt"));
                certPrivKey = RSA.Create();

                using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trusted_id_root_2022.pem"))
                {
                    StreamReader reader1 = new StreamReader(fs);
                    PemReader pem1 = new PemReader(reader1);
                    var obj = pem1.ReadPemObject();
                    certPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                    pem1.Reader.Close();
                }
            }

            BasicOcspRespGenerator respGen = new BasicOcspRespGenerator(cert.GetPublicKey());
            DateTime thisUpdate = DateTime.UtcNow;

            //var nonceExt = ocspRequest.RequestExtensions.GetExtension(OcspObjectIdentifiers.PkixOcspNonce);
            //if (nonceExt != null) respGen.SetResponseExtensions(new X509Extensions(new[] { OcspObjectIdentifiers.PkixOcspNonce }, new[] { nonceExt }));

            Req[] reqList = ocspRequest.GetRequestList();

            for (int i = 0; i < reqList.Length; i++)
            {
                Req reqCert = reqList[i];
                string serialNum = reqCert.GetCertID().SerialNumber.ToString();

                BsonDocument findResult = collection.Find(new BsonDocument { { "serialNumber", serialNum } }).FirstOrDefault();

                if (findResult == null)
                {
                    respGen.AddResponse(reqCert.GetCertID(), new UnknownStatus());
                }
                else
                {
                    if (findResult.Contains("type") && findResult["type"].IsInt32)
                    {
                        if (findResult["type"].AsInt32 == (int)type)
                        {
                            if (findResult.Contains("status") && findResult["status"].IsString)
                            {
                                if (findResult["status"].AsString == "revoked")
                                {
                                    if (findResult.Contains("revokedInfo") && findResult["revokedInfo"].IsBsonDocument)
                                    {
                                        BsonDocument revokedInfo = findResult["revokedInfo"].AsBsonDocument;
                                        if (revokedInfo.Contains("revocationDate") && revokedInfo.Contains("revocationReason"))
                                        {
                                            BsonValue rawRevocationDate = revokedInfo["revocationDate"];
                                            BsonValue rawRevocationReason = revokedInfo["revocationReason"];

                                            if (rawRevocationDate.IsBsonDateTime && rawRevocationReason.IsInt32)
                                            {
                                                DateTime revocationDate = rawRevocationDate.AsBsonDateTime.ToUniversalTime();
                                                int revocationReason = rawRevocationReason.AsInt32;

                                                if (Enum.IsDefined(typeof(CRLReason), revocationReason))
                                                {
                                                    respGen.AddResponse(reqCert.GetCertID(), new RevokedStatus(revocationDate, revocationReason), thisUpdate, thisUpdate.AddDays(14), null);
                                                }
                                                else
                                                {
                                                    respGen.AddResponse(reqCert.GetCertID(), new UnknownStatus(), thisUpdate, thisUpdate.AddDays(14), null);
                                                }
                                            }
                                            else
                                            {
                                                respGen.AddResponse(reqCert.GetCertID(), new UnknownStatus(), thisUpdate, thisUpdate.AddDays(14), null);
                                            }
                                        }
                                        else
                                        {
                                            respGen.AddResponse(reqCert.GetCertID(), new UnknownStatus(), thisUpdate, thisUpdate.AddDays(14), null);
                                        }
                                    }
                                    else
                                    {
                                        respGen.AddResponse(reqCert.GetCertID(), new UnknownStatus(), thisUpdate, thisUpdate.AddDays(14), null);
                                    }
                                }
                                else if (findResult["status"].AsString == "good")
                                {
                                    respGen.AddResponse(reqCert.GetCertID(), CertificateStatus.Good, thisUpdate, thisUpdate.AddDays(14), null);
                                }
                            }
                            else
                            {
                                respGen.AddResponse(reqCert.GetCertID(), new UnknownStatus(), thisUpdate, thisUpdate.AddDays(14), null);
                            }
                        }
                        else
                        {
                            return new OCSPRespGenerator().Generate(OcspRespStatus.Unauthorized, null).GetEncoded();
                        }
                    }
                    else
                    {
                        respGen.AddResponse(reqCert.GetCertID(), new UnknownStatus(), thisUpdate, thisUpdate.AddDays(14), null);
                    }
                }
            }

            SecureRandom rand = new SecureRandom(new CryptoApiRandomGenerator());
            Asn1SignatureFactory sig = new Asn1SignatureFactory("SHA256withRSA", DotNetUtilities.GetKeyPair(certPrivKey).Private, rand);
            //BasicOcspResp resp = respGen.Generate(sig, new[] { cert }, DateTime.UtcNow);
            BasicOcspResp resp = respGen.Generate(sig, new Org.BouncyCastle.X509.X509Certificate[] { }, thisUpdate);

            OCSPRespGenerator finalRespGen = new OCSPRespGenerator();
            return finalRespGen.Generate(OcspResponseStatus.Successful, resp).GetEncoded();
        }

        [HttpGet]
        public IActionResult Index()
        {
            if (Request.Host.ToString() != "ocsp.pki.emeraldsys.xyz") return NotFound();
            return Ok();
        }

        [HttpPost]
        public IActionResult AutoOCSPPost()
        {
            if (Request.Host.ToString() != "ocsp.pki.emeraldsys.xyz") return NotFound();

            if (Request.ContentType != "application/ocsp-request")
            {
                OCSPRespGenerator errRespGen = new OCSPRespGenerator();
                return new FileContentResult(errRespGen.Generate(OcspRespStatus.MalformedRequest, null).GetEncoded(), "application/ocsp-response");
            }

            Request.EnableBuffering();
            Stream str = Request.Body;
            str.Position = 0;
            BinaryReader reader = new BinaryReader(str);
            byte[] bRequest = reader.ReadBytes((int)Request.ContentLength);
            reader.Close();

            OcspReq req = new OcspReq(bRequest);

            byte[] bResponse = AutoGenerateOCSPResponse(req);

            return new FileContentResult(bResponse, "application/ocsp-response");
        }

        [HttpGet("trustedid_code2022")]
        public IActionResult CodeSignOCSPGet()
        {
            if (Request.Host.ToString() != "ocsp.pki.emeraldsys.xyz") return NotFound();
            return StatusCode(405, new { Success = false, Message = "GET not allowed" });
        }

        [HttpPost("trustedid_code2022")]
        public IActionResult CodeSignOCSPPost()
        {
            if (Request.Host.ToString() != "ocsp.pki.emeraldsys.xyz") return NotFound();

            if (Request.ContentType != "application/ocsp-request")
            {
                OCSPRespGenerator errRespGen = new OCSPRespGenerator();
                return new FileContentResult(errRespGen.Generate(OcspRespStatus.MalformedRequest, null).GetEncoded(), "application/ocsp-response");
            }

            Request.EnableBuffering();
            Stream str = Request.Body;
            str.Position = 0;
            BinaryReader reader = new BinaryReader(str);
            byte[] bRequest = reader.ReadBytes((int)Request.ContentLength);
            reader.Close();

            OcspReq req = new OcspReq(bRequest);

            byte[] bResponse = GenerateOCSPResponse(req, Models.CertRequest.CertificateType.CodeSigning);

            return new FileContentResult(bResponse, "application/ocsp-response");
        }

        [HttpGet("trustedid_ts2022")]
        public IActionResult TSOCSPGet()
        {
            if (Request.Host.ToString() != "ocsp.pki.emeraldsys.xyz") return NotFound();
            return StatusCode(405, new { Success = false, Message = "GET not allowed" });
        }

        [HttpPost("trustedid_ts2022")]
        public IActionResult TSOCSPPost()
        {
            if (Request.Host.ToString() != "ocsp.pki.emeraldsys.xyz") return NotFound();

            if (Request.ContentType != "application/ocsp-request")
            {
                OCSPRespGenerator errRespGen = new OCSPRespGenerator();
                return new FileContentResult(errRespGen.Generate(OcspRespStatus.MalformedRequest, null).GetEncoded(), "application/ocsp-response");
            }

            Request.EnableBuffering();
            Stream str = Request.Body;
            str.Position = 0;
            BinaryReader reader = new BinaryReader(str);
            byte[] bRequest = reader.ReadBytes((int)Request.ContentLength);
            reader.Close();

            OcspReq req = new OcspReq(bRequest);

            byte[] bResponse = GenerateOCSPResponse(req, Models.CertRequest.CertificateType.TimestampInternal);

            return new FileContentResult(bResponse, "application/ocsp-response");
        }

        [HttpGet("trustedid_dv2022")]
        public IActionResult DVOCSPGet()
        {
            if (Request.Host.ToString() != "ocsp.pki.emeraldsys.xyz") return NotFound();
            return StatusCode(405, new { Success = false, Message = "GET not allowed" });
        }

        [HttpPost("trustedid_dv2022")]
        public IActionResult DVOCSPPost()
        {
            if (Request.Host.ToString() != "ocsp.pki.emeraldsys.xyz") return NotFound();

            if (Request.ContentType != "application/ocsp-request")
            {
                OCSPRespGenerator errRespGen = new OCSPRespGenerator();
                return new FileContentResult(errRespGen.Generate(OcspRespStatus.MalformedRequest, null).GetEncoded(), "application/ocsp-response");
            }

            Request.EnableBuffering();
            Stream str = Request.Body;
            str.Position = 0;
            BinaryReader reader = new BinaryReader(str);
            byte[] bRequest = reader.ReadBytes((int)Request.ContentLength);
            reader.Close();

            OcspReq req = new OcspReq(bRequest);

            byte[] bResponse = GenerateOCSPResponse(req, Models.CertRequest.CertificateType.DomainSSL);

            return new FileContentResult(bResponse, "application/ocsp-response");
        }

        [HttpGet("trustedid_ov2022")]
        public IActionResult OVOCSPGet()
        {
            if (Request.Host.ToString() != "ocsp.pki.emeraldsys.xyz") return NotFound();
            return StatusCode(405, new { Success = false, Message = "GET not allowed" });
        }

        [HttpPost("trustedid_ov2022")]
        public IActionResult OVOCSPPost()
        {
            if (Request.Host.ToString() != "ocsp.pki.emeraldsys.xyz") return NotFound();

            if (Request.ContentType != "application/ocsp-request")
            {
                OCSPRespGenerator errRespGen = new OCSPRespGenerator();
                return new FileContentResult(errRespGen.Generate(OcspRespStatus.MalformedRequest, null).GetEncoded(), "application/ocsp-response");
            }

            Request.EnableBuffering();
            Stream str = Request.Body;
            str.Position = 0;
            BinaryReader reader = new BinaryReader(str);
            byte[] bRequest = reader.ReadBytes((int)Request.ContentLength);
            reader.Close();

            OcspReq req = new OcspReq(bRequest);

            byte[] bResponse = GenerateOCSPResponse(req, Models.CertRequest.CertificateType.OrganizationSSL);

            return new FileContentResult(bResponse, "application/ocsp-response");
        }

        [HttpGet("trusted_id_root_2022")]
        public IActionResult RootOCSPGet()
        {
            if (Request.Host.ToString() != "ocsp.pki.emeraldsys.xyz") return NotFound();
            return StatusCode(405, new { Success = false, Message = "GET not allowed" });
        }

        [HttpPost("trusted_id_root_2022")]
        public IActionResult RootOCSPPost()
        {
            if (Request.Host.ToString() != "ocsp.pki.emeraldsys.xyz") return NotFound();

            if (Request.ContentType != "application/ocsp-request")
            {
                OCSPRespGenerator errRespGen = new OCSPRespGenerator();
                return new FileContentResult(errRespGen.Generate(OcspRespStatus.MalformedRequest, null).GetEncoded(), "application/ocsp-response");
            }

            Request.EnableBuffering();
            Stream str = Request.Body;
            str.Position = 0;
            BinaryReader reader = new BinaryReader(str);
            byte[] bRequest = reader.ReadBytes((int)Request.ContentLength);
            reader.Close();

            OcspReq req = new OcspReq(bRequest);

            byte[] bResponse = GenerateOCSPResponse(req, Models.CertRequest.CertificateType.IntermediateRoot2022);

            return new FileContentResult(bResponse, "application/ocsp-response");
        }
    }
}
