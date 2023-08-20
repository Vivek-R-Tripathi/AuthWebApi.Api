namespace AuthWebApi.Api.Model.Dto
{

    //this model need to send as a response in login
    public class TokenApiDto
    {
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
    }
}
