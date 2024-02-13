using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using BrokenAuthenticationSample.Data;
using Microsoft.AspNetCore.CookiePolicy;
using BrokenAuthenticationSample.Contract.Email;
using Serilog;
using BrokenAuthenticationSample.Helper;
var builder = WebApplication.CreateBuilder(args);
var connectionString = builder.Configuration.GetConnectionString("BrokenAuthenticationSampleContextConnection") ?? throw new InvalidOperationException("Connection string 'BrokenAuthenticationSampleContextConnection' not found.");
// Configure Serilog
builder.Host.UseSerilog((ctx, lc) => lc
    .WriteTo.Console()
    .WriteTo.File($"logs/log.txt", rollingInterval: RollingInterval.Day));
builder.Services.AddDbContext<BrokenAuthenticationSampleContext>(options => options.UseSqlServer(connectionString));
// Bind SMTP settings
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true).AddEntityFrameworkStores<BrokenAuthenticationSampleContext>();

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddTransient<IEmailSender, EmailSender>();

var sendGridKey = builder.Configuration["SendGridKey"];
if (string.IsNullOrEmpty(sendGridKey))
{
    throw new InvalidOperationException("SendGridKey is not configured.");
}

builder.Services.AddTransient<IEmailSender, EmailSender>();

builder.Services.Configure<IdentityOptions>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    // ... other password options

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
});
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30); // Set the expiration timespan for the authentication cookie
    options.LoginPath = "/Account/Login"; // Set the login path
    options.LogoutPath = "/Account/Logout"; // Set the logout path
    options.SlidingExpiration = true; // The cookie would be re-issued on any request half way through the ExpireTimeSpan
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Enforce HTTPS
});
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");


app.Run();
