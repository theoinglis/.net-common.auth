namespace Common.Auth.Hashing
{
    public interface IHashService
    {
        string HashText(string text);
    }
}
