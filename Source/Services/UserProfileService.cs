using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Codenation.Challenge.Models;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Validation;

namespace Codenation.Challenge.Services
{
    public class UserProfileService : IProfileService
    {
        private CodenationContext codenationContext;
        public UserProfileService(CodenationContext dbContext)
        {
            this.codenationContext = dbContext;
        }

        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var request = context.ValidatedRequest as ValidatedTokenRequest;

            if (request != null)
            {
                var user = codenationContext.Users.FirstOrDefault(x => x.Email == request.UserName);
                if (user != null)
                    context.AddRequestedClaims(GetUserClaims(user));
            }

            return Task.CompletedTask;

        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            context.IsActive = true;
            return Task.CompletedTask;
        }

        public static Claim[] GetUserClaims(User user)
        {
            return new[]
            {
                new Claim(ClaimTypes.Name, user.Nickname ?? ""),
                new Claim(ClaimTypes.Email, user.Email.TrimEnd() ?? ""),
                new Claim(ClaimTypes.Role, "user")
            };
        }

    }
}