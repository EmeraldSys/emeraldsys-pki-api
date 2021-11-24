using System;
using System.IO;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using MongoDB.Driver;
using Newtonsoft.Json;
using JWT;

namespace EmeraldSysPKIBackend.Controllers
{
    [Route("v1/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private MongoClient client;

        public AuthController()
        {
            MongoClientSettings settings = MongoClientSettings.FromConnectionString(Environment.GetEnvironmentVariable("MONGODB_AUTH_STR"));
            client = new MongoClient(settings);
        }

        public class AccountRequest
        {
            [JsonProperty("user")]
            public string User { get; set; }
            [JsonProperty("pass")]
            public string Password { get; set; }
        }

        public class AccountToken
        {
            [JsonProperty("uid")]
            public int UserId { get; set; }
            [JsonProperty("user")]
            public string User { get; set; }
            [JsonProperty("entropy")]
            public int Entropy { get; set; }
            [JsonProperty("admin")]
            public bool Admin { get; set; }
        }

        public enum AuthenticateResult
        {
            SUCCESS,
            SESSION_EXPIRED,
            SIGNATURE_INVALID,
            UNKNOWN
        }

        public static AuthenticateResult Authenticate(string token, out AccountToken user)
        {
            try
            {
                IJsonSerializer serializer = new JWT.Serializers.JsonNetSerializer();
                IDateTimeProvider provider = new UtcDateTimeProvider();
                IJwtValidator validator = new JwtValidator(serializer, provider);
                IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                JWT.Algorithms.IJwtAlgorithm algorithm = new JWT.Algorithms.HMACSHA256Algorithm();
                IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);

                string decoded = decoder.Decode(token, Environment.GetEnvironmentVariable("JWT_SECRET"), true);

                user = JsonConvert.DeserializeObject<AccountToken>(decoded);
                return AuthenticateResult.SUCCESS;
            }
            catch (JWT.Exceptions.TokenExpiredException)
            {
                user = null;
                return AuthenticateResult.SESSION_EXPIRED;
            }
            catch (JWT.Exceptions.SignatureVerificationException)
            {
                user = null;
                return AuthenticateResult.SIGNATURE_INVALID;
            }
            catch (Exception)
            {
                user = null;
                return AuthenticateResult.UNKNOWN;
            }
        }

        [HttpPost("login")]
        [EnableCors("default")]
        public IActionResult Login()
        {
            Stream str = Request.Body;
            string json = new StreamReader(str).ReadToEnd();

            AccountRequest req = JsonConvert.DeserializeObject<AccountRequest>(json);

            if (req != null && !string.IsNullOrEmpty(req.User) && !string.IsNullOrEmpty(req.Password))
            {
                IMongoDatabase database = client.GetDatabase("main");
                IMongoCollection<BsonDocument> collection = database.GetCollection<BsonDocument>("users");

                BsonDocument user = collection.Find(new BsonDocument { { "user", req.User } }).FirstOrDefault();

                if (user != null)
                {
                    if (user.Contains("uid") && user["uid"].IsInt32 && user.Contains("pass") && user["pass"].IsString)
                    {
                        if (BCrypt.Net.BCrypt.Verify(req.Password, user["pass"].AsString))
                        {
                            string token = JWT.Builder.JwtBuilder.Create()
                                .WithAlgorithm(new JWT.Algorithms.HMACSHA256Algorithm())
                                .WithSecret(Environment.GetEnvironmentVariable("JWT_SECRET"))
                                .AddClaim("exp", DateTimeOffset.UtcNow.AddHours(2).ToUnixTimeSeconds())
                                .AddClaim("uid", user["uid"].AsInt32)
                                .AddClaim("user", req.User)
                                .AddClaim("admin", (user.Contains("admin") && user["admin"].IsBoolean) ? user["admin"].AsBoolean : false)
                                .AddClaim("entropy", new Random().Next(1, 87686112))
                                .Encode();

                            return Ok(new { Success = true, Token = token });
                        }
                        else
                        {
                            return StatusCode(403, new { Success = false, Message = "Hash validation failed" });
                        }
                    }
                    else
                    {
                        return BadRequest(new { Success = false });
                    }
                }
                else
                {
                    return NotFound(new { Success = false, Message = "User not found" });
                }
            }
            else
            {
                return BadRequest(new { Success = false });
            }
        }

        [HttpGet("verify")]
        [EnableCors("default")]
        public IActionResult Verify([FromQuery]string token)
        {
            if (!string.IsNullOrEmpty(token))
            {
                try
                {
                    IJsonSerializer serializer = new JWT.Serializers.JsonNetSerializer();
                    IDateTimeProvider provider = new UtcDateTimeProvider();
                    IJwtValidator validator = new JwtValidator(serializer, provider);
                    IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                    JWT.Algorithms.IJwtAlgorithm algorithm = new JWT.Algorithms.HMACSHA256Algorithm();
                    IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);

                    string decoded = decoder.Decode(token, Environment.GetEnvironmentVariable("JWT_SECRET"), true);

                    return Ok(new { Success = true, Decoded = JsonConvert.DeserializeObject(decoded) });
                }
                catch (JWT.Exceptions.TokenExpiredException)
                {
                    return StatusCode(403, new { Success = false, Message = "Token expired" });
                }
                catch (JWT.Exceptions.SignatureVerificationException)
                {
                    return StatusCode(403, new { Success = false, Message = "Signature verification failed" });
                }
                catch (Exception ex)
                {
                    return StatusCode(500, new { Success = false, Message = ex.Message });
                }
            }

            return BadRequest(new { Success = false });
        }

        [HttpPost("register")]
        [EnableCors("default")]
        public IActionResult Register()
        {
            Stream str = Request.Body;
            string json = new StreamReader(str).ReadToEnd();

            AccountRequest req = JsonConvert.DeserializeObject<AccountRequest>(json);

            if (req != null && !string.IsNullOrEmpty(req.User) && !string.IsNullOrEmpty(req.Password))
            {
                IMongoDatabase database = client.GetDatabase("main");
                IMongoCollection<BsonDocument> collection = database.GetCollection<BsonDocument>("users");

                BsonDocument user = collection.Find(new BsonDocument { { "user", req.User } }).FirstOrDefault();

                if (user == null)
                {
                    string hash = BCrypt.Net.BCrypt.HashPassword(req.Password);
                    if (!string.IsNullOrEmpty(hash))
                    {
                        collection.InsertOne(new BsonDocument { { "user", req.User }, { "pass", hash } });
                        return StatusCode(201, new { Success = true, Message = "Registration successful" });
                    }
                    else
                    {
                        return StatusCode(500, new { Success = false, Message = "Hash generation failed" });
                    }
                }
                else
                {
                    return BadRequest(new { Success = false, Message = "User exists" });
                }
            }
            else
            {
                return BadRequest(new { Success = false });
            }
        }
    }
}
