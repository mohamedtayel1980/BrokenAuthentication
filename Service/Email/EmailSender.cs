using BrokenAuthenticationSample.Contract.Email;
using BrokenAuthenticationSample.Controllers;
using NuGet.Common;
using SendGrid;
using SendGrid.Helpers.Mail;

public class EmailSender : IEmailSender
{
    private readonly SendGridClient _client;
    private readonly EmailAddress _fromAddress;
    private readonly ILogger<EmailSender> _logger;

    public EmailSender(IConfiguration configuration, ILogger<EmailSender> logger)
    {
        var apiKey = configuration.GetValue<string>("SendGridKey");
        _logger = logger;
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            throw new ArgumentException("SendGrid API key is not configured.");
        }

        _client = new SendGridClient(apiKey);

        var fromEmail = configuration.GetValue<string>("EmailSettings:SenderEmail");
        var fromName = configuration.GetValue<string>("EmailSettings:SenderName");
        _fromAddress = new EmailAddress(fromEmail, fromName);
    }

    public ILogger<EmailSender> Logger => _logger;

    public async Task SendEmailAsync(string toEmail, string subject, string htmlMessage)
    {
        var to = new EmailAddress(toEmail);
        var msg = MailHelper.CreateSingleEmail(_fromAddress, to, subject, "", htmlMessage);
        var response = await _client.SendEmailAsync(msg);
        _logger.LogInformation($"MFA token: {response}");
    }
}
