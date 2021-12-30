using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using MongoDB.Driver;

namespace EmeraldSysPKIBackend.Controllers
{
    [Route("v1/auth/keys")]
    [ApiController]
    public class AuthKeyController : ControllerBase
    {
        private MongoClient client;
        private static Random r;
        
        public AuthKeyController()
        {
            MongoClientSettings settings = MongoClientSettings.FromConnectionString(Environment.GetEnvironmentVariable("MONGODB_AUTH_STR"));
            client = new MongoClient(settings);

            r = new Random();
        }
        
        [HttpGet]
        [EnableCors("default")]
        public IActionResult ListApiKeys()
        {
            if (!Request.Headers.ContainsKey("X-API-KEY"))
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
                            AuthController.AuthenticateResult ret =
                                AuthController.Authenticate(token, out AuthController.AccountToken user);

                            if (ret == AuthController.AuthenticateResult.SUCCESS)
                            {
                                IMongoDatabase database = client.GetDatabase("main");
                                IMongoCollection<BsonDocument> collection =
                                    database.GetCollection<BsonDocument>("users");

                                BsonDocument result = collection.Find(new BsonDocument {{"uid", user.UserId}})
                                    .FirstOrDefault();

                                if (result != null)
                                {
                                    if (result.Contains("keys") && result["keys"].IsBsonArray)
                                    {
                                        BsonArray userKeyArray = result["keys"].AsBsonArray;
                                        if (userKeyArray.All(key => key.IsString)) // probably unnecessary
                                        {
                                            List<string> keyList = new List<string>();
                                            for (int i = 0; i < userKeyArray.Count; i++)
                                            {
                                                string val = userKeyArray[i].AsString;
                                                keyList.Add(val);
                                            }

                                            return Ok(new {Success = true, Data = keyList.ToArray()});
                                        }
                                    }
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
            }

            return BadRequest(new { Success = false });
        }
        
        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[r.Next(s.Length)]).ToArray());
        }

        [HttpPut("generate")]
        [EnableCors("default")]
        public IActionResult NewApiKey()
        {
            if (!Request.Headers.ContainsKey("X-API-KEY"))
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
                            AuthController.AuthenticateResult ret =
                                AuthController.Authenticate(token, out AuthController.AccountToken user);

                            if (ret == AuthController.AuthenticateResult.SUCCESS)
                            {
                                IMongoDatabase database = client.GetDatabase("main");
                                IMongoCollection<BsonDocument> collection =
                                    database.GetCollection<BsonDocument>("users");

                                string apiKey = RandomString(20);
                                
                                FilterDefinition<BsonDocument> filter = Builders<BsonDocument>.Filter.Eq("uid", user.UserId);
                                UpdateDefinition<BsonDocument> update =
                                    Builders<BsonDocument>.Update.Push("keys", apiKey);

                                var result = collection.UpdateOne(filter, update);

                                if (result.IsAcknowledged && result.ModifiedCount >= 1)
                                {
                                    return StatusCode(201, new {Success = true, Data = apiKey});
                                }
                                else
                                {
                                    return StatusCode(500, new { Success = false });
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
            }

            return BadRequest(new { Success = false });
        }
    }
}