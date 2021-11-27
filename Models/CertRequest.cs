using System;
using Newtonsoft.Json;

namespace EmeraldSysPKIBackend.Models
{
    public class CertRequest
    {
        public enum CertificateType
        {
            DomainSSL,
            OrganizationSSL,
            EVSSL,
            EVCodeSigning,
            CodeSigning,
            TimestampInternal,
            IntermediateRoot2022,
            EVSSL2
        }

        public enum SignatureAlgorithm
        {
            SHA256withRSA,
            SHA384withRSA
        }

        [JsonProperty("type")]
        public CertificateType Type { get; set; } = CertificateType.DomainSSL;
        [JsonProperty("algorithm")]
        public SignatureAlgorithm Algorithm { get; set; } = SignatureAlgorithm.SHA256withRSA;
        [JsonIgnore]
        public bool EV { get => Type == CertificateType.EVSSL || Type == CertificateType.EVCodeSigning; }
        [JsonProperty("email")]
        public string Email { get; set; }
        [JsonProperty("commonName")]
        public string CommonName { get; set; }
        [JsonProperty("organization")]
        public string Organization { get; set; } = "N/A";
        [JsonProperty("organizationUnits")]
        public string[] OrganizationUnits { get; set; }
        [JsonProperty("locality")]
        public string Locality { get; set; }
        [JsonProperty("state")]
        public string State { get; set; }
        [JsonProperty("country")]
        public string Country { get; set; }
        [JsonProperty("subjectAltNames")]
        public string[] SubjectAltNames { get; set; }
        public string CSR { get; set; }
        [JsonProperty("notAfter")]
        public string NotAfter { get; set; } // UTC Timestamp
        [JsonProperty("notAfterYears")]
        public int NotAfterYears { get; set; } = 0;

        public override string ToString()
        {
            string Result = $"{{Type = \"{Type}\", CommonName = \"{CommonName}\", Organization = \"{Organization}\", OrganizationUnits = [";

            for (int i = 0; i < OrganizationUnits.Length; i++)
            {
                if (i == (OrganizationUnits.Length - 1))
                {
                    Result += $"\"{OrganizationUnits[i]}\"]";
                }
                else
                {
                    Result += $"\"{OrganizationUnits[i]}\", ";
                }
            }

            Result += "}";

            return Result;
        }
    }
}
