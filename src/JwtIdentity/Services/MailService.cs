using System.Net;
using System.Net.Mail;
using System.Text;

namespace JwtIdentity.Services;

public class MailService
{
    public string SendVerification(string from, string password, string to, string verificationLink)
    {
        var otp = (OtpRandom.NextInt() % 1000000).ToString("000000");

        using (MailMessage mail = new MailMessage())
        {
            mail.From = new MailAddress(from);
            
            mail.To.Add(to);
            
            mail.Subject = "Email address verification";
            
            mail.Body = $"<h1>Your email verification code: <code>{otp}</code></h1>";
            
            mail.IsBodyHtml = true;

            mail.BodyEncoding = Encoding.UTF8;

            mail.DeliveryNotificationOptions = DeliveryNotificationOptions.OnFailure;

            using (SmtpClient client = new SmtpClient("smtp.gmail.com", 587))
            {
                client.EnableSsl = true;

                client.UseDefaultCredentials = false;

                client.DeliveryMethod = SmtpDeliveryMethod.Network;
                
                client.Credentials = new NetworkCredential(from, password);
                
                client.Send(mail);
            }
        }

        return otp;
    }
}
