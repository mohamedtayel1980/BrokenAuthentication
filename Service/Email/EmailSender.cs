using BrokenAuthenticationSample.Contract.Email;
using BrokenAuthenticationSample.Helper;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
public class EmailSender : IEmailSender
{

    private readonly ILogger<EmailSender> _logger;
    private readonly SmtpSettings _smtpSettings;
    public EmailSender(IOptions<SmtpSettings> smtpSettings, ILogger<EmailSender> logger)
    {

        _logger = logger;
        _smtpSettings = smtpSettings.Value;
    }



    public async Task SendEmailAsync(string toEmail, string subject, string message)
    {
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        var smtpClient = new SmtpClient(_smtpSettings.Server)
        {
            Port = _smtpSettings.Port,
            Credentials = new NetworkCredential(_smtpSettings.Username, _smtpSettings.Password),
            UseDefaultCredentials = _smtpSettings.SMTPAuthentication,
            EnableSsl = _smtpSettings.EnableSsl,
            DeliveryMethod = SmtpDeliveryMethod.Network
        };

        var mailMessage = new MailMessage
        {
            From = new MailAddress(_smtpSettings.FromAddress, _smtpSettings.FromName),
            Subject = subject,
            Body = message,
            IsBodyHtml = true,
        };
        mailMessage.To.Add(toEmail);

        await smtpClient.SendMailAsync(mailMessage);
    }
}
