﻿/*
 * EmeraldSys PKI
 * Certs API
 *
 * Copyright (c) 2021-2022 EmeraldSys, All rights reserved
*/

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using Amazon;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using MongoDB.Bson;
using MongoDB.Driver;
using JWT;

using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;

namespace EmeraldSysPKIBackend.Controllers
{
    [Route("v1/certs")]
    [ApiController]
    public class CertsController : ControllerBase
    {
        private readonly MongoClient client;
        private readonly AmazonS3Client s3Client;

        public CertsController()
        {
            BasicAWSCredentials creds = new BasicAWSCredentials(Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID"), Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY"));

            s3Client = new AmazonS3Client(creds, RegionEndpoint.USWest1);
            
            MongoClientSettings settings = MongoClientSettings.FromConnectionString(Environment.GetEnvironmentVariable("MONGODB_AUTH_STR"));
            client = new MongoClient(settings);
        }

        public class CertReq
        {
            public Models.CertRequest Req { get; }
            public Org.BouncyCastle.X509.X509Certificate IssuerCert { get; }
            public RSA IssuerPrivKey { get; }
            public ECDsa IssuerPrivKeyEC { get; }

            public CertReq(Models.CertRequest Req, Org.BouncyCastle.X509.X509Certificate IssuerCert, RSA IssuerPrivKey)
            {
                this.Req = Req;
                this.IssuerCert = IssuerCert;
                this.IssuerPrivKey = IssuerPrivKey;
            }

            public CertReq(Models.CertRequest Req, Org.BouncyCastle.X509.X509Certificate IssuerCert, ECDsa IssuerPrivKeyEC)
            {
                this.Req = Req;
                this.IssuerCert = IssuerCert;
                this.IssuerPrivKeyEC = IssuerPrivKeyEC;
            }
        }

        public class CALoadResult
        {
            public Org.BouncyCastle.X509.X509Certificate Certificate { get; }
            public RSA PrivateKey { get; }
            public ECDsa PrivateKeyEC { get; }

            public CALoadResult(Org.BouncyCastle.X509.X509Certificate Certificate, RSA PrivateKey)
            {
                this.Certificate = Certificate;
                this.PrivateKey = PrivateKey;
            }

            public CALoadResult(Org.BouncyCastle.X509.X509Certificate Certificate, ECDsa PrivateKeyEC)
            {
                this.Certificate = Certificate;
                this.PrivateKeyEC = PrivateKeyEC;
            }
        }

        // Used for returning both certificate and private key in PEM format
        public class CertResult
        {
            public Org.BouncyCastle.Math.BigInteger SerialNumber { get; }
            public string Certificate { get; }
            public string PrivateKey { get; }

            public CertResult(string Certificate, string PrivateKey)
            {
                this.Certificate = Certificate;
                this.PrivateKey = PrivateKey;

                using (StringReader reader = new StringReader(Certificate))
                {
                    PemReader pem = new PemReader(reader);
                    var obj = pem.ReadPemObject();
                    var temp = new Org.BouncyCastle.X509.X509Certificate(obj.Content);
                    SerialNumber = temp.SerialNumber;
                    pem.Reader.Close();
                }
            }
        }

        public CALoadResult LoadCA(Models.CertRequest.CertificateType type)
        {
            Org.BouncyCastle.X509.X509Certificate caCert = null;
            RSA caCertPrivKey = null;
            ECDsa caCertPrivKeyEC = null;

            if (type == Models.CertRequest.CertificateType.CodeSigning)
            {
                caCert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trustedid_code2022.crt"));
                caCertPrivKey = RSA.Create();

                using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trustedid_code2022.pem"))
                {
                    StreamReader reader = new StreamReader(fs);
                    PemReader pem = new PemReader(reader);
                    var obj = pem.ReadPemObject();
                    caCertPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                    pem.Reader.Close();
                    fs.Close();
                }
            }
            else if (type == Models.CertRequest.CertificateType.TimestampInternal)
            {
                caCert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trustedid_ts2022.crt"));
                caCertPrivKey = RSA.Create();

                using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trustedid_ts2022.pem"))
                {
                    StreamReader reader = new StreamReader(fs);
                    PemReader pem = new PemReader(reader);
                    var obj = pem.ReadPemObject();
                    caCertPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                    pem.Reader.Close();
                    fs.Close();
                }
            }
            else if (type == Models.CertRequest.CertificateType.IntermediateSSLRoot2022 ||
                type == Models.CertRequest.CertificateType.IntermediateCSRoot2022)
            {
                caCert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trusted_id_root_2022.crt"));
                caCertPrivKey = RSA.Create();

                using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trusted_id_root_2022.pem"))
                {
                    StreamReader reader = new StreamReader(fs);
                    PemReader pem = new PemReader(reader);
                    var obj = pem.ReadPemObject();
                    caCertPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                    pem.Reader.Close();
                    fs.Close();
                }
            }
            else if (type == Models.CertRequest.CertificateType.IntermediateSSLECCRoot2022 ||
                type == Models.CertRequest.CertificateType.IntermediateCSECCRoot2022)
            {
                caCert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trusted_id_root_ecc_2022.crt"));
                caCertPrivKeyEC = ECDsa.Create();

                using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trusted_id_root_ecc_2022.pem"))
                {
                    StreamReader reader = new StreamReader(fs);
                    PemReader pem = new PemReader(reader);
                    var obj = pem.ReadPemObject();
                    caCertPrivKeyEC.ImportECPrivateKey(obj.Content, out _);
                    pem.Reader.Close();
                    fs.Close();
                }

                return new CALoadResult(caCert, caCertPrivKeyEC);
            }
            else if (type == Models.CertRequest.CertificateType.DomainSSL)
            {
                caCert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trustedid_dv2022.crt"));
                caCertPrivKey = RSA.Create();

                using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trustedid_dv2022.pem"))
                {
                    StreamReader reader = new StreamReader(fs);
                    PemReader pem = new PemReader(reader);
                    var obj = pem.ReadPemObject();
                    caCertPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                    pem.Reader.Close();
                    fs.Close();
                }
            }
            else if (type == Models.CertRequest.CertificateType.OrganizationSSL)
            {
                caCert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trustedid_ov2022.crt"));
                caCertPrivKey = RSA.Create();

                using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trustedid_ov2022.pem"))
                {
                    StreamReader reader = new StreamReader(fs);
                    PemReader pem = new PemReader(reader);
                    var obj = pem.ReadPemObject();
                    caCertPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                    pem.Reader.Close();
                    fs.Close();
                }
            }
            else if (type == Models.CertRequest.CertificateType.EVSSL)
            {
                caCert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trustedid_ev2022.crt"));
                caCertPrivKey = RSA.Create();

                using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trustedid_ev2022.pem"))
                {
                    StreamReader reader = new StreamReader(fs);
                    PemReader pem = new PemReader(reader);
                    var obj = pem.ReadPemObject();
                    caCertPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                    pem.Reader.Close();
                    fs.Close();
                }
            }
            else if (type == Models.CertRequest.CertificateType.EVSSL2)
            {
                caCert = DotNetUtilities.FromX509Certificate(new X509Certificate2(Program.CURRENT_DIR + @"/ca/trustedid_ev2_2022.crt"));
                caCertPrivKey = RSA.Create();

                using (FileStream fs = System.IO.File.OpenRead(Program.CURRENT_DIR + @"/ca/trustedid_ev2_2022.pem"))
                {
                    StreamReader reader = new StreamReader(fs);
                    PemReader pem = new PemReader(reader);
                    var obj = pem.ReadPemObject();
                    caCertPrivKey.ImportRSAPrivateKey(obj.Content, out _);
                    pem.Reader.Close();
                    fs.Close();
                }
            }
            else
            {
                return null;
            }

            return new CALoadResult(caCert, caCertPrivKey);
        }

        public CertResult GenerateCert(CertReq req)
        {
            IMongoDatabase database = client.GetDatabase("main");
            IMongoCollection<BsonDocument> collection = database.GetCollection<BsonDocument>("certificateRequests");

            X509V3CertificateGenerator cert = new X509V3CertificateGenerator();

            Org.BouncyCastle.Math.BigInteger serialNum = Org.BouncyCastle.Math.BigInteger.ProbablePrime(120, new Random());
            cert.SetSerialNumber(serialNum);

            List<string> dnStructure = new List<string>();

            if (req.Req.Type != Models.CertRequest.CertificateType.DomainSSL)
            {
                if (string.IsNullOrEmpty(req.Req.Country) || string.IsNullOrEmpty(req.Req.State) || string.IsNullOrEmpty(req.Req.Locality) || string.IsNullOrEmpty(req.Req.Organization))
                {
                    return null;
                }

                if (req.Req.Type == Models.CertRequest.CertificateType.EVSSL || req.Req.Type == Models.CertRequest.CertificateType.EVSSL2)
                {
                    dnStructure.Add($"2.5.4.15=Private Organization"); // businessCategory
                    dnStructure.Add($"1.3.6.1.4.1.311.60.2.1.3={req.Req.Country}"); // jurisdictionCountryName
                    dnStructure.Add($"1.3.6.1.4.1.311.60.2.1.2={req.Req.State}"); // jurisdictionStateOrProvinceName
                    dnStructure.Add($"SERIALNUMBER={new Random().Next(306000, 612000)}");
                }

                if (req.Req.Country.Length == 2)
                {
                    dnStructure.Add($"C={req.Req.Country}");
                }

                dnStructure.Add($"ST={req.Req.State}");
                dnStructure.Add($"L={req.Req.Locality}");
                dnStructure.Add($"O={req.Req.Organization}");

                if (req.Req.OrganizationUnits != null && !(req.Req.OrganizationUnits.Length > 2))
                {
                    for (int i = 0; i < req.Req.OrganizationUnits.Length; i++)
                    {
                        dnStructure.Add($"OU={req.Req.OrganizationUnits[i]}");
                    }
                }
            }

            dnStructure.Add($"CN={req.Req.CommonName}");

            cert.SetSubjectDN(new X509Name(string.Join(",", dnStructure)));
            cert.SetIssuerDN(req.IssuerCert.SubjectDN);

            DateTime genTime = DateTime.UtcNow;
            cert.SetNotBefore(genTime);

            if (!string.IsNullOrEmpty(req.Req.NotAfter) && DateTime.TryParse(req.Req.NotAfter, out DateTime ret))
            {
                if (ret > genTime)
                {
                    cert.SetNotAfter(ret);
                }
            }
            else if (req.Req.NotAfterYears > 0)
            {
                cert.SetNotAfter(genTime.AddYears(req.Req.NotAfterYears));
            }
            else
            {
                cert.SetNotAfter(genTime.AddYears(1));
            }

            SecureRandom rand = new SecureRandom(new CryptoApiRandomGenerator());

            RsaKeyPairGenerator keyPairGen = new RsaKeyPairGenerator();

            // Code signing certificates should have a 4096 bit length
            KeyGenerationParameters keyGenParams = new KeyGenerationParameters(rand, req.Req.Type == Models.CertRequest.CertificateType.CodeSigning || req.Req.Type == Models.CertRequest.CertificateType.EVCodeSigning ? 4096 : 2048);

            keyPairGen.Init(keyGenParams);
            AsymmetricCipherKeyPair kp = keyPairGen.GenerateKeyPair();

            AsymmetricKeyParameter publicKey = kp.Public;

            cert.SetPublicKey(publicKey);

            cert.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(publicKey));
            cert.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(req.IssuerCert));

            if (req.Req.Type == Models.CertRequest.CertificateType.CodeSigning || req.Req.Type == Models.CertRequest.CertificateType.EVCodeSigning)
            {
                cert.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.IdKPCodeSigning));
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.TimestampInternal)
            {
                cert.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeID.IdKPTimeStamping));
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.IntermediateSSLRoot2022 || req.Req.Type == Models.CertRequest.CertificateType.IntermediateSSLECCRoot2022)
            {
                // TODO: Add custom extended key usages
                cert.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPClientAuth));
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.IntermediateCSRoot2022 || req.Req.Type == Models.CertRequest.CertificateType.IntermediateCSECCRoot2022)
            {
                cert.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.IdKPCodeSigning));
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.OrganizationSSL || req.Req.Type == Models.CertRequest.CertificateType.EVSSL || req.Req.Type == Models.CertRequest.CertificateType.EVSSL2)
            {
                cert.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.IdKPClientAuth, KeyPurposeID.IdKPServerAuth));
            }

            if ((req.Req.Type == Models.CertRequest.CertificateType.CodeSigning || req.Req.Type == Models.CertRequest.CertificateType.EVCodeSigning) && !string.IsNullOrEmpty(req.Req.Email))
            {
                GeneralName emailName = new GeneralName(GeneralName.Rfc822Name, req.Req.Email);
                GeneralNames subjectAltName = new GeneralNames(emailName);
                cert.AddExtension(X509Extensions.SubjectAlternativeName, false, subjectAltName);
            }
            else if (
                req.Req.Type == Models.CertRequest.CertificateType.DomainSSL ||
                req.Req.Type == Models.CertRequest.CertificateType.OrganizationSSL ||
                req.Req.Type == Models.CertRequest.CertificateType.EVSSL ||
                req.Req.Type == Models.CertRequest.CertificateType.EVSSL2)
            {
                List<GeneralName> dnsNames = new List<GeneralName>() { new GeneralName(GeneralName.DnsName, req.Req.CommonName) };

                if (req.Req.SubjectAltNames != null)
                {
                    for (int i = 0; i < req.Req.SubjectAltNames.Length; i++)
                    {
                        string dnsPointName = req.Req.SubjectAltNames[i];
                        if (dnsPointName != req.Req.CommonName)
                        {
                            if (Uri.CheckHostName(dnsPointName) == UriHostNameType.Dns)
                            {
                                GeneralName dnsName = new GeneralName(GeneralName.DnsName, dnsPointName);
                                dnsNames.Add(dnsName);
                            }
                        }
                    }
                }

                GeneralNames subjectAltName = new GeneralNames(dnsNames.ToArray());
                cert.AddExtension(X509Extensions.SubjectAlternativeName, false, subjectAltName);
            }

            GeneralName crlGeneralName = null;
            GeneralName crtGeneralName = null;
            GeneralName ocspGeneralName = null;

            if (req.Req.Type == Models.CertRequest.CertificateType.CodeSigning)
            {
                crlGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crl.pki.emeraldsys.xyz/trustedid_code2022.crl");
                crtGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crt.pki.emeraldsys.xyz/trustedid_code2022.crt");
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.TimestampInternal)
            {
                crlGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crl.pki.emeraldsys.xyz/trustedid_ts2022.crl");
                crtGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crt.pki.emeraldsys.xyz/trustedid_ts2022.crt");
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.IntermediateSSLRoot2022 ||
                req.Req.Type == Models.CertRequest.CertificateType.IntermediateCSRoot2022)
            {
                crlGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crl.pki.emeraldsys.xyz/trusted_id_root_2022.crl");
                crtGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crt.pki.emeraldsys.xyz/trusted_id_root_2022.crt");
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.IntermediateSSLECCRoot2022 ||
                req.Req.Type == Models.CertRequest.CertificateType.IntermediateCSECCRoot2022)
            {
                crlGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crl.pki.emeraldsys.xyz/trusted_id_root_ecc_2022.crl");
                crtGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crt.pki.emeraldsys.xyz/trusted_id_root_ecc_2022.crt");
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.DomainSSL)
            {
                crlGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crl.pki.emeraldsys.xyz/trustedid_dv2022.crl");
                crtGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crt.pki.emeraldsys.xyz/trustedid_dv2022.crt");
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.OrganizationSSL)
            {
                crlGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crl.pki.emeraldsys.xyz/trustedid_ov2022.crl");
                crtGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crt.pki.emeraldsys.xyz/trustedid_ov2022.crt");
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.EVSSL)
            {
                crlGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crl.pki.emeraldsys.xyz/trustedid_ev2022.crl");
                crtGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crt.pki.emeraldsys.xyz/trustedid_ev2022.crt");
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.EVSSL2)
            {
                crlGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crl.pki.emeraldsys.xyz/trustedid_ev2_2022.crl");
                crtGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://crt.pki.emeraldsys.xyz/trustedid_ev2_2022.crt");
            }

            if (crlGeneralName != null)
            {
                DistributionPointName crlName = new DistributionPointName(DistributionPointName.FullName, crlGeneralName);
                DistributionPoint crl = new DistributionPoint(crlName, null, null);
                cert.AddExtension(X509Extensions.CrlDistributionPoints, false, new CrlDistPoint(new[] { crl }));
            }

            ocspGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, "http://ocsp.pki.emeraldsys.xyz");

            if (crtGeneralName != null && ocspGeneralName != null)
            {
                AccessDescription caIssuers = new AccessDescription(X509ObjectIdentifiers.IdADCAIssuers, crtGeneralName);
                AccessDescription ocsp = new AccessDescription(X509ObjectIdentifiers.IdADOcsp, ocspGeneralName);
                AuthorityInformationAccess aia = new AuthorityInformationAccess(new[] { caIssuers, ocsp });
                cert.AddExtension(X509Extensions.AuthorityInfoAccess, false, aia);
            }

            if (req.Req.Type == Models.CertRequest.CertificateType.CodeSigning)
            {
                PolicyInformation inf = new PolicyInformation(new DerObjectIdentifier("2.23.140.1.4.1"));
                cert.AddExtension(X509Extensions.CertificatePolicies, false, new CertificatePolicies(inf));
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.EVCodeSigning)
            {
                PolicyInformation inf = new PolicyInformation(new DerObjectIdentifier("2.23.140.1.3"));
                cert.AddExtension(X509Extensions.CertificatePolicies, false, new CertificatePolicies(inf));
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.IntermediateSSLRoot2022 ||
                req.Req.Type == Models.CertRequest.CertificateType.IntermediateCSRoot2022 ||
                req.Req.Type == Models.CertRequest.CertificateType.IntermediateSSLECCRoot2022 ||
                req.Req.Type == Models.CertRequest.CertificateType.IntermediateCSECCRoot2022)
            {
                PolicyInformation inf = new PolicyInformation(new DerObjectIdentifier("2.5.29.32.0"));
                cert.AddExtension(X509Extensions.CertificatePolicies, false, new CertificatePolicies(inf));
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.DomainSSL)
            {
                PolicyInformation inf = new PolicyInformation(new DerObjectIdentifier("2.23.140.1.2.1"));
                cert.AddExtension(X509Extensions.CertificatePolicies, false, new CertificatePolicies(inf));
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.OrganizationSSL)
            {
                PolicyInformation inf = new PolicyInformation(new DerObjectIdentifier("2.23.140.1.2.2"));
                cert.AddExtension(X509Extensions.CertificatePolicies, false, new CertificatePolicies(inf));
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.EVSSL || req.Req.Type == Models.CertRequest.CertificateType.EVSSL2)
            {
                PolicyInformation inf = new PolicyInformation(new DerObjectIdentifier("2.23.140.1.1"));
                PolicyInformation inf2 = new PolicyInformation(new DerObjectIdentifier("2.16.124.1.918311.1.1"));
                cert.AddExtension(X509Extensions.CertificatePolicies, false, new CertificatePolicies(new[] { inf, inf2 }));
            }

            if (req.Req.Type == Models.CertRequest.CertificateType.IntermediateSSLRoot2022 ||
                req.Req.Type == Models.CertRequest.CertificateType.IntermediateCSRoot2022 ||
                req.Req.Type == Models.CertRequest.CertificateType.IntermediateSSLECCRoot2022 ||
                req.Req.Type == Models.CertRequest.CertificateType.IntermediateCSECCRoot2022)
            {
                cert.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            }
            else
            {
                cert.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            }

            if (req.Req.Type == Models.CertRequest.CertificateType.CodeSigning || req.Req.Type == Models.CertRequest.CertificateType.EVCodeSigning || req.Req.Type == Models.CertRequest.CertificateType.TimestampInternal)
            {
                cert.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage((int)X509KeyUsageFlags.DigitalSignature));
            }
            else if (req.Req.Type == Models.CertRequest.CertificateType.IntermediateSSLRoot2022 ||
                req.Req.Type == Models.CertRequest.CertificateType.IntermediateCSRoot2022 ||
                req.Req.Type == Models.CertRequest.CertificateType.IntermediateSSLECCRoot2022 ||
                req.Req.Type == Models.CertRequest.CertificateType.IntermediateCSECCRoot2022)
            {
                cert.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage((int)X509KeyUsageFlags.DigitalSignature | (int)X509KeyUsageFlags.KeyCertSign | (int)X509KeyUsageFlags.CrlSign));
            }
            else if (
                req.Req.Type == Models.CertRequest.CertificateType.DomainSSL ||
                req.Req.Type == Models.CertRequest.CertificateType.OrganizationSSL ||
                req.Req.Type == Models.CertRequest.CertificateType.EVSSL ||
                req.Req.Type == Models.CertRequest.CertificateType.EVSSL2)
            {
                cert.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage((int)X509KeyUsageFlags.DigitalSignature | (int)X509KeyUsageFlags.KeyEncipherment));
            }

            Asn1SignatureFactory sig = null;

            switch (req.Req.Algorithm)
            {
                case Models.CertRequest.SignatureAlgorithm.SHA256withRSA:
                    sig = new Asn1SignatureFactory("SHA256withRSA", DotNetUtilities.GetKeyPair(req.IssuerPrivKey).Private);
                    break;
                case Models.CertRequest.SignatureAlgorithm.SHA384withRSA:
                    sig = new Asn1SignatureFactory("SHA384withRSA", DotNetUtilities.GetKeyPair(req.IssuerPrivKey).Private);
                    break;
                case Models.CertRequest.SignatureAlgorithm.SHA256withECDSA:
                    sig = new Asn1SignatureFactory("SHA256withECDSA", DotNetUtilities.GetKeyPair(req.IssuerPrivKeyEC).Private);
                    break;
                default:
                    break;
            }
            
            if (sig != null)
            {
                var genCert = cert.Generate(sig);

                BsonArray OUArray = new BsonArray();
                if (req.Req.OrganizationUnits != null)
                {
                    foreach (string unit in req.Req.OrganizationUnits)
                    {
                        OUArray.Add(unit);
                    }
                }

                BsonArray SubjectAltArray = new BsonArray();
                if (req.Req.SubjectAltNames != null)
                {
                    foreach (string name in req.Req.SubjectAltNames)
                    {
                        SubjectAltArray.Add(name);
                    }
                }

                collection.InsertOne(new BsonDocument
                {
                    { "serialNumber", serialNum.ToString() },
                    { "subject", new BsonDocument {
                        { "commonName", req.Req.CommonName },
                        { "subjectAltNames", SubjectAltArray },
                        { "organization", req.Req.Organization },
                        { "organizationUnits", OUArray },
                        { "locality", req.Req.Type != Models.CertRequest.CertificateType.DomainSSL ? req.Req.Locality : "N/A" },
                        { "state", req.Req.Type != Models.CertRequest.CertificateType.DomainSSL ? req.Req.State : "N/A" },
                        { "country", req.Req.Type != Models.CertRequest.CertificateType.DomainSSL ? req.Req.Country : "N/A" }
                    } },
                    { "type", (int)req.Req.Type },
                    { "status", "good" }
                });

                MemoryStream mem1 = new MemoryStream();
                StreamWriter writer1 = new StreamWriter(mem1);
                PemWriter pemCertWriter = new PemWriter(writer1);
                pemCertWriter.WriteObject(genCert);
                pemCertWriter.Writer.Flush();

                StreamReader reader1 = new StreamReader(mem1);
                mem1.Position = 0;
                string pemCert = reader1.ReadToEnd();
                reader1.Close();

                MemoryStream mem2 = new MemoryStream();
                StreamWriter writer2 = new StreamWriter(mem2);
                PemWriter pemKeyWriter = new PemWriter(writer2);
                pemKeyWriter.WriteObject(kp.Private);
                pemKeyWriter.Writer.Flush();

                StreamReader reader2 = new StreamReader(mem2);
                mem2.Position = 0;
                string pemKey = reader2.ReadToEnd();
                reader2.Close();

                return new CertResult(pemCert, pemKey);
            }

            return null;
        }

        [HttpGet("csr")]
        public IActionResult CSRGet()
        {
            return StatusCode(405, new { Success = false, Message = "GET not allowed" });
        }

        [HttpPost("csr")]
        public IActionResult CSRPost()
        {
            Request.EnableBuffering();
            Stream str = Request.Body;
            str.Position = 0;
            string json = new StreamReader(str).ReadToEnd();

            Models.CertRequest req = JsonConvert.DeserializeObject<Models.CertRequest>(json);

            if (!string.IsNullOrEmpty(req.CommonName))
            {
                List<string> dnStructure = new List<string>();

                if (!string.IsNullOrEmpty(req.Country)) dnStructure.Add($"C={req.Country}");
                if (!string.IsNullOrEmpty(req.State)) dnStructure.Add($"ST={req.State}");
                if (!string.IsNullOrEmpty(req.Locality)) dnStructure.Add($"L={req.Locality}");
                if (!string.IsNullOrEmpty(req.Organization)) dnStructure.Add($"O={req.Organization}");

                dnStructure.Add($"CN={req.CommonName}");

                X509Name subject = new X509Name(string.Join(",", dnStructure));

                SecureRandom rand = new SecureRandom(new CryptoApiRandomGenerator());
                RsaKeyPairGenerator keyPairGen = new RsaKeyPairGenerator();
                KeyGenerationParameters keyGenParams = new KeyGenerationParameters(rand, 2048);
                keyPairGen.Init(keyGenParams);
                AsymmetricCipherKeyPair kp = keyPairGen.GenerateKeyPair();

                Pkcs10CertificationRequest csr = new Pkcs10CertificationRequest("SHA256withRSA", subject, kp.Public, null, kp.Private);

                MemoryStream mem1 = new MemoryStream();
                StreamWriter writer1 = new StreamWriter(mem1);
                PemWriter pemCsrWriter = new PemWriter(writer1);
                pemCsrWriter.WriteObject(csr);
                pemCsrWriter.Writer.Flush();

                StreamReader reader1 = new StreamReader(mem1);
                mem1.Position = 0;
                string pemCsr = reader1.ReadToEnd();
                reader1.Close();

                MemoryStream mem2 = new MemoryStream();
                StreamWriter writer2 = new StreamWriter(mem2);
                PemWriter pemKeyWriter = new PemWriter(writer2);
                pemKeyWriter.WriteObject(kp.Private);
                pemKeyWriter.Writer.Flush();

                StreamReader reader2 = new StreamReader(mem2);
                mem2.Position = 0;
                string pemKey = reader2.ReadToEnd();
                reader2.Close();

                return StatusCode(201, new { Success = true, Info = new { CSR = pemCsr, PrivKey = pemKey } });
            }

            return BadRequest();
        }

        [HttpGet("request")]
        public IActionResult RequestGet()
        {
            return StatusCode(405, new { Success = false, Message = "GET not allowed" });
        }

        [HttpPost("request")]
        public async Task<IActionResult> RequestPost()
        {
            IMongoDatabase database = client.GetDatabase("main");
            IMongoCollection<BsonDocument> collection = database.GetCollection<BsonDocument>("certificateRequests");

            Request.EnableBuffering();
            Stream str = Request.Body;
            str.Position = 0;
            string json = new StreamReader(str).ReadToEnd();

            Models.CertRequest req = JsonConvert.DeserializeObject<Models.CertRequest>(json);

            if (!string.IsNullOrEmpty(req.CSR))
            {
                Pkcs10CertificationRequest decoded;

                using (StringReader reader = new StringReader(req.CSR))
                {
                    PemReader pem = new PemReader(reader);
                    var obj = pem.ReadPemObject();
                    decoded = new Pkcs10CertificationRequest(obj.Content);
                    pem.Reader.Close();
                }

                if (decoded != null && decoded.Verify())
                {
                    if (req.Type == Models.CertRequest.CertificateType.DomainSSL && !string.IsNullOrEmpty(req.Email))
                    {
                        //AsymmetricKeyParameter kp = decoded.GetPublicKey();
                        //RsaKeyParameters kpParams = (RsaKeyParameters)kp;

                        //if (kpParams.Modulus.BitLength != 4096) return StatusCode(400, new { Success = false, Message = "Invalid CSR - Key size is not 4096 bits" });

                        var Info = decoded.GetCertificationRequestInfo();

                        string CommonName = Info.Subject.GetValueList(X509Name.CN).OfType<string>().FirstOrDefault();

                        if (Uri.CheckHostName(CommonName) == UriHostNameType.Dns)
                        {
                            string SerialNumber = Org.BouncyCastle.Math.BigInteger.ProbablePrime(120, new Random()).ToString();
                            string hash = "";

                            using (SHA512 sha = SHA512.Create())
                            {
                                byte[] b = System.Text.Encoding.UTF8.GetBytes(SerialNumber.ToString());
                                byte[] hashArr = sha.ComputeHash(b);
                                foreach (byte bt in hashArr)
                                {
                                    hash += bt.ToString("X2");
                                }
                                hash = hash.ToLower();
                                sha.Clear();
                            }

                            BsonDocument newDocument = new BsonDocument
                            {
                                { "serialNumber", SerialNumber },
                                { "type", (int)Models.CertRequest.CertificateType.DomainSSL },
                                { "email", req.Email },
                                { "fields", new BsonDocument
                                    {
                                        { "commonName", CommonName }
                                    }
                                },
                                { "status", "pending" },
                                { "hash", hash }
                            };

                            collection.InsertOne(newDocument);

                            HttpClient httpClient = new HttpClient();
                            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("api:dad7075ccaf1305ed27d913f7cef735d-2bf328a5-a2e1f589")));

                            MultipartFormDataContent form = new MultipartFormDataContent();

                            form.Add(new StringContent("PKINoReply <no-reply@pki.emeraldsys.xyz>"), "from");
                            form.Add(new StringContent(req.Email), "to");
                            form.Add(new StringContent($"Certificate pending - {CommonName}"), "subject");
                            form.Add(new StringContent($"Hello,<br />A certificate has been requested for the domain name \"{CommonName}\". If you did not make this request, you can safely ignore this.<br /><br />https://api.pki.emeraldsys.xyz/v1/certs/emailDcv?hash={hash}"), "html");

                            HttpResponseMessage resp = await httpClient.PostAsync("https://api.mailgun.net/v3/pki.emeraldsys.xyz/messages", form);

                            Console.Write(resp.Content.ReadAsStringAsync().Result);

                            return StatusCode(201, new { Success = true, Message = "Certificate is now pending" });
                        }
                        else
                        {
                            return StatusCode(400, new { Success = false, Message = "Invalid CSR - Domain name does not match type Dns" });
                        }
                    }
                    else
                    {
                        return StatusCode(400, new { Success = false, Message = "Invalid type - Domain SSL is the only supported type at the moment" });
                    }
                }
                else
                {
                    return StatusCode(400, new { Success = false, Message = "Invalid CSR - Could not convert or verify" });
                }
            }

            return StatusCode(500);
        }

        [HttpGet("emailDcv")]
        public async Task<IActionResult> EmailDcvGet([FromQuery]string hash)
        {
            IMongoDatabase database = client.GetDatabase("main");
            IMongoCollection<BsonDocument> collection = database.GetCollection<BsonDocument>("certificateRequests");

            BsonDocument request = collection.Find(new BsonDocument { { "hash", hash } }).FirstOrDefault();

            if (request != null)
            {
                if (request.Contains("serialNumber") && request.Contains("email") && request.Contains("fields"))
                {
                    if (request["serialNumber"].IsString && request["email"].IsString)
                    {
                        string serialNum = request["serialNumber"].AsString;
                        string email = request["email"].AsString;

                        if (request.Contains("type") && request["type"].IsInt32)
                        {
                            int type = request["type"].AsInt32;
                            if (Enum.IsDefined(typeof(Models.CertRequest.CertificateType), type))
                            {
                                if (request.Contains("fields") && request["fields"].IsBsonDocument)
                                {
                                    BsonDocument fields = request["fields"].AsBsonDocument;
                                    if (fields.Contains("commonName") && fields["commonName"].IsString)
                                    {
                                        string commonName = fields["commonName"].AsString;
                                        Models.CertRequest certRequest = new Models.CertRequest
                                        {
                                            Type = (Models.CertRequest.CertificateType)type,
                                            Email = email,
                                            CommonName = commonName
                                        };

                                        CALoadResult result = LoadCA((Models.CertRequest.CertificateType)type);

                                        if (result != null)
                                        {
                                            CertResult generated = GenerateCert(new CertReq(certRequest, result.Certificate, result.PrivateKey));

                                            byte[] certBytes = System.Text.Encoding.UTF8.GetBytes(generated.Certificate);

                                            var ret = collection.UpdateOne(new BsonDocument { { "hash", hash } }, new UpdateDefinitionBuilder<BsonDocument>().Set("status", "good"));
                                            if ((int)ret.ModifiedCount > 0)
                                            {
                                                HttpClient httpClient = new HttpClient();
                                                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("api:dad7075ccaf1305ed27d913f7cef735d-2bf328a5-a2e1f589")));

                                                MultipartFormDataContent form = new MultipartFormDataContent();

                                                form.Add(new StringContent("PKINoReply <no-reply@pki.emeraldsys.xyz>"), "from");
                                                form.Add(new StringContent(email), "to");
                                                form.Add(new StringContent($"Certificate issued - {commonName}"), "subject");
                                                form.Add(new StringContent($"Hello,<br />A certificate has been issued for the domain name \"{commonName}\"."), "html", "certificate.crt");
                                                form.Add(new ByteArrayContent(certBytes, 0, certBytes.Length), "attachment");

                                                await httpClient.PostAsync("https://api.mailgun.net/v3/pki.emeraldsys.xyz/messages", form);

                                                return Ok(new { Success = true, Message = "Domain control has been validated" });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return BadRequest();
        }

        [HttpGet("generate")]
        public IActionResult GenerateGet()
        {
            return StatusCode(405, new { Success = false, Message = "GET not allowed" });
        }

        [HttpPost("generate")]
        public async Task<IActionResult> GeneratePost()
        {
            if (Request.Headers.TryGetValue("Authorization", out Microsoft.Extensions.Primitives.StringValues v))
            {
                string value = v.First();
                string[] split = value.Split(" ");

                if (split[0] == "Bearer")
                {
                    string token = split[1];

                    if (!string.IsNullOrEmpty(token))
                    {
                        AuthController.AuthenticateResult ret = AuthController.Authenticate(token, out AuthController.AccountToken user);

                        if (ret == AuthController.AuthenticateResult.SUCCESS)
                        {
                            if (user.Admin)
                            {
                                Request.EnableBuffering();
                                Stream str = Request.Body;
                                str.Position = 0;
                                string json = new StreamReader(str).ReadToEnd();

                                Models.CertRequest req = JsonConvert.DeserializeObject<Models.CertRequest>(json);

                                Console.WriteLine(!string.IsNullOrEmpty(req.CommonName) && string.IsNullOrEmpty(req.CSR));
                                if (!string.IsNullOrEmpty(req.CommonName) && string.IsNullOrEmpty(req.CSR))
                                {
                                    Org.BouncyCastle.X509.X509Certificate caCert = null;
                                    RSA caCertPrivKey = null;

                                    UriHostNameType commonNameType = Uri.CheckHostName(req.CommonName);

                                    Console.WriteLine(commonNameType);
                                    if (commonNameType == UriHostNameType.Unknown)
                                    {
                                        if (req.Type == Models.CertRequest.CertificateType.CodeSigning)
                                        {
                                            CALoadResult result = LoadCA(Models.CertRequest.CertificateType.CodeSigning);

                                            if (result != null)
                                            {
                                                caCert = result.Certificate;
                                                caCertPrivKey = result.PrivateKey;
                                            }
                                        }
                                        else if (req.Type == Models.CertRequest.CertificateType.TimestampInternal)
                                        {
                                            CALoadResult result = LoadCA(Models.CertRequest.CertificateType.TimestampInternal);

                                            if (result != null)
                                            {
                                                caCert = result.Certificate;
                                                caCertPrivKey = result.PrivateKey;
                                            }
                                        }
                                        else if (req.Type == Models.CertRequest.CertificateType.IntermediateSSLRoot2022 ||
                                            req.Type == Models.CertRequest.CertificateType.IntermediateCSRoot2022)
                                        {
                                            CALoadResult result = LoadCA(Models.CertRequest.CertificateType.IntermediateSSLRoot2022);

                                            if (result != null)
                                            {
                                                caCert = result.Certificate;
                                                caCertPrivKey = result.PrivateKey;
                                            }
                                        }
                                        else if (req.Type == Models.CertRequest.CertificateType.IntermediateSSLECCRoot2022 ||
                                            req.Type == Models.CertRequest.CertificateType.IntermediateCSECCRoot2022)
                                        {
                                            CALoadResult result = LoadCA(Models.CertRequest.CertificateType.IntermediateSSLECCRoot2022);

                                            if (result != null)
                                            {
                                                caCert = result.Certificate;
                                                caCertPrivKey = result.PrivateKey;
                                            }
                                        }
                                    }
                                    else if (commonNameType == UriHostNameType.Dns)
                                    {
                                        CALoadResult result = LoadCA(req.Type);

                                        if (result != null)
                                        {
                                            caCert = result.Certificate;
                                            caCertPrivKey = result.PrivateKey;
                                        }
                                    }

                                    if (caCert != null && caCertPrivKey != null)
                                    {
                                        CertResult generated = GenerateCert(new CertReq(req, caCert, caCertPrivKey));

                                        if (generated != null)
                                        {
                                            MemoryStream mem = new MemoryStream();
                                            StreamWriter writer = new StreamWriter(mem);
                                            await writer.WriteAsync(generated.Certificate);
                                            await writer.FlushAsync();
                                            mem.Position = 0;
                                            
                                            await s3Client.PutObjectAsync(new PutObjectRequest()
                                            {
                                                BucketName = "userstorage-pki",
                                                ContentType = "application/x-x509-ca-cert",
                                                InputStream = mem,
                                                Key = generated.SerialNumber.ToString() + ".crt"
                                            });
                                            
                                            return StatusCode(201, new { Success = true, Info = new { Certificate = generated.Certificate, PrivKey = generated.PrivateKey } });
                                        }
                                    }
                                }

                                return BadRequest(new { });
                            }
                            else
                            {
                                return StatusCode(403, new { Success = false, Message = "Insufficient permissions" });
                            }
                        }
                        else if (ret == AuthController.AuthenticateResult.SESSION_EXPIRED)
                        {
                            return StatusCode(403, new { Success = false, Message = "Token expired" });
                        }
                        else if (ret == AuthController.AuthenticateResult.SIGNATURE_INVALID)
                        {
                            return StatusCode(403, new { Success = false, Message = "Signature verification failed" });
                        }
                        else if (ret == AuthController.AuthenticateResult.UNKNOWN)
                        {
                            return StatusCode(500, new { Success = false });
                        }
                    }
                }
            }

            return Unauthorized(new { Success = false });
        }

        // Returns a list of certificates for the authenticated user
        [HttpGet]
        [EnableCors("default")]
        public IActionResult CertList()
        {
            if (Request.Headers.TryGetValue("Authorization", out Microsoft.Extensions.Primitives.StringValues v))
            {
                string value = v.First();
                string[] split = value.Split(" ");
                
                if (split[0] == "Bearer")
                {
                    string token = split[1];

                    if (!string.IsNullOrEmpty(token))
                    {
                        AuthController.AuthenticateResult result = AuthController.Authenticate(token, out AuthController.AccountToken user);

                        if (result == AuthController.AuthenticateResult.SUCCESS)
                        {
                            IMongoDatabase database = client.GetDatabase("main");
                            IMongoCollection<BsonDocument> collection = database.GetCollection<BsonDocument>("certificateRequests");

                            List<BsonDocument> certs = collection.Find(new BsonDocument { { "uid", user.UserId } }).ToList();

                            return Ok(new { Success = true, Info = certs });
                        }
                        else if (result == AuthController.AuthenticateResult.SESSION_EXPIRED)
                        {
                            return StatusCode(403, new { Success = false, Message = "Token expired" });
                        }
                        else if (result == AuthController.AuthenticateResult.SIGNATURE_INVALID)
                        {
                            return StatusCode(403, new { Success = false, Message = "Signature verification failed" });
                        }
                        else if (result == AuthController.AuthenticateResult.UNKNOWN)
                        {
                            return StatusCode(500, new { Success = false });
                        }
                    }
                }
            }

            return Unauthorized(new { Success = false });
        }

        [HttpGet("{serialNumber}/status")]
        public IActionResult CertStatus(string serialNumber)
        {
            if (Request.Headers.TryGetValue("Authorization", out Microsoft.Extensions.Primitives.StringValues v))
            {
                string value = v.First();
                string[] split = value.Split(" ");

                if (split[0] == "Bearer")
                {
                    string token = split[1];

                    if (!string.IsNullOrEmpty(token))
                    {
                        AuthController.AuthenticateResult ret = AuthController.Authenticate(token, out AuthController.AccountToken user);

                        if (ret == AuthController.AuthenticateResult.SUCCESS)
                        {
                            IMongoDatabase database = client.GetDatabase("main");
                            IMongoCollection<BsonDocument> collection = database.GetCollection<BsonDocument>("certificateRequests");

                            string serialNum = "";

                            if (Regex.IsMatch(serialNumber, @"[0-9]*[a-f][0-9a-f]*"))
                            {
                                serialNum = System.Numerics.BigInteger.Parse(serialNumber, System.Globalization.NumberStyles.AllowHexSpecifier).ToString();
                            }
                            else
                            {
                                serialNum = serialNumber;
                            }

                            BsonDocument result = collection.Find(new BsonDocument { { "serialNumber", serialNum } }).FirstOrDefault();

                            if (result != null)
                            {
                                if (result.Contains("status") && result["status"].IsString)
                                {
                                    int uid = result["uid"].AsInt32;
                                    if (user.UserId == uid)
                                    {
                                        return Ok(new { Success = true, Info = new { Status = result["status"].AsString } });
                                    }
                                }
                            }

                            return NotFound(new { Success = false, Message = "No certificate was found with this serial number" });
                        }
                        else if (ret == AuthController.AuthenticateResult.SESSION_EXPIRED)
                        {
                            return StatusCode(403, new { Success = false, Message = "Token expired" });
                        }
                        else if (ret == AuthController.AuthenticateResult.SIGNATURE_INVALID)
                        {
                            return StatusCode(403, new { Success = false, Message = "Signature verification failed" });
                        }
                        else if (ret == AuthController.AuthenticateResult.UNKNOWN)
                        {
                            return StatusCode(500, new { Success = false });
                        }
                    }
                }
            }

            return Unauthorized(new { Success = false });
        }

        [HttpGet("{serialNumber}/download")]
        public async Task<IActionResult> CertDownload(string serialNumber)
        {
            IMongoDatabase database = client.GetDatabase("main");
            IMongoCollection<BsonDocument> collection = database.GetCollection<BsonDocument>("certificateRequests");
            
            string serialNum = "";

            if (Regex.IsMatch(serialNumber, @"[0-9]*[a-f][0-9a-f]*"))
            {
                serialNum = System.Numerics.BigInteger.Parse(serialNumber, NumberStyles.AllowHexSpecifier).ToString();
            }
            else
            {
                serialNum = serialNumber;
            }

            BsonDocument result = collection.Find(new BsonDocument { { "serialNumber", serialNum } }).FirstOrDefault();

            if (result != null)
            {
                try
                {
                    GetObjectResponse certFile = await s3Client.GetObjectAsync(new GetObjectRequest()
                    {
                        BucketName = "userstorage-pki",
                        Key = serialNum + ".crt"
                    });

                    return File(certFile.ResponseStream, certFile.Headers.ContentType, certFile.Key);
                }
                catch (AmazonS3Exception ex)
                {
                    return StatusCode(500,
                        new
                        {
                            Success = false, Message = "S3 Internal Error",
                            Info = new { StatusCode = ex.StatusCode, Message = ex.Message }
                        });
                }
            }
            
            return NotFound(new { Success = false, Message = "No certificate was found with this serial number" });
        }

        public class RevokeRequest
        {
            [JsonProperty("revocationDate")]
            public string Date { get; set; }
            [JsonProperty("revocationReason")]
            public OCSPController.CRLReason Reason { get; set; }
        }

        [HttpDelete("{serialNumber}/revoke")]
        public IActionResult CertRevoke(string serialNumber)
        {
            if (Request.Headers.TryGetValue("Authorization", out Microsoft.Extensions.Primitives.StringValues v))
            {
                string value = v.First();
                string[] split = value.Split(" ");

                if (split[0] == "Bearer")
                {
                    string token = split[1];

                    if (!string.IsNullOrEmpty(token))
                    {
                        AuthController.AuthenticateResult ret = AuthController.Authenticate(token, out AuthController.AccountToken user);

                        if (ret == AuthController.AuthenticateResult.SUCCESS)
                        {
                            Request.EnableBuffering();
                            Stream str = Request.Body;
                            str.Position = 0;
                            string json = new StreamReader(str).ReadToEnd();

                            RevokeRequest req = JsonConvert.DeserializeObject<RevokeRequest>(json);

                            IMongoDatabase database = client.GetDatabase("main");
                            IMongoCollection<BsonDocument> collection = database.GetCollection<BsonDocument>("certificateRequests");

                            string serialNum = "";

                            if (Regex.IsMatch(serialNumber, @"[0-9]*[a-f][0-9a-f]*"))
                            {
                                serialNum = System.Numerics.BigInteger.Parse(serialNumber, System.Globalization.NumberStyles.AllowHexSpecifier).ToString();
                            }
                            else
                            {
                                serialNum = serialNumber;
                            }

                            BsonDocument result = collection.Find(new BsonDocument { { "serialNumber", serialNum } }).FirstOrDefault();

                            if (result != null)
                            {
                                if (result.Contains("uid") && result["uid"].IsInt32)
                                {
                                    int uid = result["uid"].AsInt32;
                                    if (user.UserId == uid || user.Admin)
                                    {
                                        if (DateTime.TryParseExact(req.Date, "yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out DateTime date))
                                        {
                                            if (Enum.IsDefined(typeof(OCSPController.CRLReason), req.Reason))
                                            {
                                                UpdateDefinition<BsonDocument> upd = Builders<BsonDocument>.Update.Set("status", "revoked").Set("revokedInfo", new BsonDocument { { "revocationDate", date }, { "revocationReason", (int)req.Reason } });
                                                collection.UpdateOne(new BsonDocument { { "serialNumber", serialNum } }, upd);
                                                return NoContent();
                                            }
                                            else
                                            {
                                                return BadRequest(new { Success = false, Message = "Revocation reason not defined in enum" });
                                            }
                                        }
                                        else
                                        {
                                            return BadRequest(new { Success = false, Message = "Date cannot be parsed" });
                                        }
                                    }
                                    else
                                    {
                                        return StatusCode(403, new { Success = false, Message = "Missing access" });
                                    }
                                }
                                else if (user.Admin)
                                {
                                    if (DateTime.TryParseExact(req.Date, "yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out DateTime date))
                                    {
                                        if (Enum.IsDefined(typeof(OCSPController.CRLReason), req.Reason))
                                        {
                                            UpdateDefinition<BsonDocument> upd = Builders<BsonDocument>.Update.Set("status", "revoked").Set("revokedInfo", new BsonDocument { { "revocationDate", date }, { "revocationReason", (int)req.Reason } });
                                            collection.UpdateOne(new BsonDocument { { "serialNumber", serialNum } }, upd);
                                            return NoContent();
                                        }
                                        else
                                        {
                                            return BadRequest(new { Success = false, Message = "Revocation reason not defined in enum" });
                                        }
                                    }
                                    else
                                    {
                                        return BadRequest(new { Success = false, Message = "Date cannot be parsed" });
                                    }
                                }
                                else
                                {
                                    return BadRequest(new { Success = false, Message = "Certificate is not user created" });
                                }
                            }

                            return NotFound(new { Success = false, Message = "No certificate was found with this serial number" });
                        }
                        else if (ret == AuthController.AuthenticateResult.SESSION_EXPIRED)
                        {
                            return StatusCode(403, new { Success = false, Message = "Token expired" });
                        }
                        else if (ret == AuthController.AuthenticateResult.SIGNATURE_INVALID)
                        {
                            return StatusCode(403, new { Success = false, Message = "Signature verification failed" });
                        }
                        else if (ret == AuthController.AuthenticateResult.UNKNOWN)
                        {
                            return StatusCode(500, new { Success = false });
                        }
                    }
                }
            }

            return Unauthorized(new { Success = false });
        }
    }
}
