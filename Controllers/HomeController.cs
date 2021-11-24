using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace EmeraldSysPKIBackend.Controllers
{
    [Route("")]
    [ApiController]
    public class HomeController : ControllerBase
    {
        [HttpGet]
        public IActionResult Index()
        {
            return Ok(new { });
        }
    }
}
