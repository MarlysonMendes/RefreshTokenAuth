using ApiAuth.Models;

namespace ApiAuth.Repositories
{
    public static class UserRepository
    {
        public static User GetUser(string username, string password)
        { 
            var users = new List<User>();
            users.Add(new User { Id = 1, Username = "admin", Password = "admin", Role = "manager" });
            users.Add(new User {Id =2, Username ="Marlyson", Password = "Marlyson", Role = "employee" });
            return users.FirstOrDefault(u => 
                u.Username == username && u.Password == password);       
        }
    }
}