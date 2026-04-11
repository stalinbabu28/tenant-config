import nodemailer from "nodemailer";

const transporter = (() => {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    return null;
  }

  return nodemailer.createTransport({
    secure: true,
    host: "smtp.gmail.com",
    port: 465,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
})();

export const sendOTPEmail = async (email, otp) => {
  if (!transporter) {
    throw new Error("Email transport is not configured");
  }

  const htmlTemplate = `
    <!DOCTYPE html>
    <html>
      <body style="margin:0; padding:0; background-color:#0f172a; font-family:Arial, sans-serif; color:#e5e7eb;">
        <table align="center" width="100%" cellpadding="0" cellspacing="0" style="padding:40px 0;">
          <tr>
            <td align="center">
              <table width="420" cellpadding="0" cellspacing="0" style="background-color:#111827; border-radius:12px; padding:30px; box-shadow:0 10px 25px rgba(0,0,0,0.5);">
                <tr>
                  <td style="text-align:center; padding-bottom:20px;">
                    <h2 style="margin:0; color:#f9fafb; font-weight:600;">Verification Code</h2>
                    <p style="margin:8px 0 0; font-size:14px; color:#9ca3af;">Use the code below to continue</p>
                  </td>
                </tr>
                <tr>
                  <td style="text-align:center; padding:20px 0;">
                    <div style="display:inline-block; background:#1f2937; padding:16px 28px; border-radius:8px; letter-spacing:6px; font-size:28px; font-weight:bold; color:#38bdf8;">${otp}</div>
                  </td>
                </tr>
                <tr>
                  <td style="text-align:center; font-size:14px; color:#9ca3af; padding-bottom:20px;">This code will expire in <span style="color:#fbbf24;">5 minutes</span>.</td>
                </tr>
                <tr>
                  <td style="text-align:center; font-size:13px; color:#6b7280;">Do not share this code with anyone for security reasons.</td>
                </tr>
                <tr>
                  <td style="padding:20px 0;"><hr style="border:none; border-top:1px solid #1f2937;"></td>
                </tr>
                <tr>
                  <td style="text-align:center; font-size:12px; color:#6b7280;">If you didn’t request this, you can safely ignore this email.</td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
    </html>
  `;

  await transporter.sendMail({
    to: email,
    subject: "Your TenantConfig Login Code",
    text: `Your verification code is ${otp}. It expires in 5 minutes.`,
    html: htmlTemplate,
  });
};
