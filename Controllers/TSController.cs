using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace EmeraldSysPKIBackend.Controllers
{
    [Route("v1/ts")]
    [ApiController]
    public class TSController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            if (Request.Host.ToString() != "ts.pki.emeraldsys.xyz") return NotFound();
            return Ok("Timestamp Server - SHA256");
        }

        [HttpGet("sha384")]
        public IActionResult Get384()
        {
            if (Request.Host.ToString() != "ts.pki.emeraldsys.xyz") return NotFound();
            return Ok("Timestamp Server - SHA384");
        }

        [HttpPost]
        public IActionResult Post([FromQuery]string time)
        {
            if (Request.Host.ToString() != "ts.pki.emeraldsys.xyz") return NotFound();

            Request.EnableBuffering();
            Request.Body.Position = 0;

            TSResponder responder = new TSResponder(System.IO.File.ReadAllBytes(Program.CURRENT_DIR + @"ts/ts_new.crt"), System.IO.File.ReadAllBytes(Program.CURRENT_DIR + @"ts/ts_new.pem"), "SHA256");

            BinaryReader reader = new BinaryReader(Request.Body);
            byte[] bRequest = reader.ReadBytes((int)Request.ContentLength);
            reader.Close();

            DateTime signTime = DateTime.UtcNow;
            if (time != null)
            {
                if (!DateTime.TryParseExact(time, "yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out signTime))
                {
                    signTime = DateTime.UtcNow;
                }
            }

            bool RFC;
            byte[] bResponse = responder.GenResponse(bRequest, signTime, out RFC);

            responder = null;

            MemoryStream mem = new MemoryStream();

            BinaryWriter writer = new BinaryWriter(mem);
            writer.Write(bResponse);

            mem.Position = 0;

            return new FileStreamResult(mem, new Microsoft.Net.Http.Headers.MediaTypeHeaderValue(RFC ? "application/timestamp-reply" : "application/octet-stream"));
        }

        [HttpPost("sha384")]
        public IActionResult Post384([FromQuery]string time)
        {
            if (Request.Host.ToString() != "ts.pki.emeraldsys.xyz") return NotFound();

            Request.EnableBuffering();
            Request.Body.Position = 0;

            TSResponder responder = new TSResponder(System.IO.File.ReadAllBytes(Program.CURRENT_DIR + @"ts/ts_new_sha384.crt"), System.IO.File.ReadAllBytes(Program.CURRENT_DIR + @"ts/ts_new_sha384.pem"), "SHA256");

            BinaryReader reader = new BinaryReader(Request.Body);
            byte[] bRequest = reader.ReadBytes((int)Request.ContentLength);
            reader.Close();

            DateTime signTime = DateTime.UtcNow;
            if (time != null)
            {
                if (!DateTime.TryParseExact(time, "yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out signTime))
                {
                    signTime = DateTime.UtcNow;
                }
            }

            bool RFC;
            byte[] bResponse = responder.GenResponse(bRequest, signTime, out RFC);

            responder = null;

            MemoryStream mem = new MemoryStream();

            BinaryWriter writer = new BinaryWriter(mem);
            writer.Write(bResponse);

            mem.Position = 0;

            return new FileStreamResult(mem, new Microsoft.Net.Http.Headers.MediaTypeHeaderValue(RFC ? "application/timestamp-reply" : "application/octet-stream"));
        }
    }
}
