import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import sgMail from '@sendgrid/mail';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import * as Handlebars from 'handlebars';

export interface EmailOptions {
  to: string;
  subject: string;
  template: string;
  context: Record<string, unknown>;
}

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private readonly templatesPath: string;
  private readonly from: string;
  private readonly fromName: string;
  private readonly replyTo: string;
  private readonly enabled: boolean;

  constructor(private readonly configService: ConfigService) {
    // Initialize SendGrid
    const apiKey = this.configService.get<string>('SENDGRID_API_KEY');
    if (apiKey) {
      sgMail.setApiKey(apiKey);
      this.enabled = true;
    } else {
      this.logger.warn('SendGrid API key not configured. Email sending is disabled.');
      this.enabled = false;
    }

    // Email configuration
    this.from = this.configService.get<string>('EMAIL_FROM', 'noreply@example.com');
    this.fromName = this.configService.get<string>('EMAIL_FROM_NAME', 'TodoApp');
    this.replyTo = this.configService.get<string>('EMAIL_REPLY_TO', this.from);
    this.templatesPath = resolve(__dirname, 'templates');
  }

  /**
   * Send an email using a template
   */
  async sendEmail(options: EmailOptions): Promise<void> {
    if (!this.enabled) {
      this.logger.log(`Email sending disabled. Would have sent email to: ${options.to}`);
      this.logger.log(`Subject: ${options.subject}`);
      this.logger.log(`Template: ${options.template}`);
      this.logger.log(`Context: ${JSON.stringify(options.context)}`);
      return;
    }

    try {
      // Load and compile template
      const templatePath = resolve(this.templatesPath, `${options.template}.hbs`);
      const templateSource = readFileSync(templatePath, 'utf-8');
      const template = Handlebars.compile(templateSource);

      // Add common variables to context
      const context = {
        ...options.context,
        year: new Date().getFullYear(),
        replyTo: this.replyTo,
      };

      // Render HTML
      const html = template(context);

      // Send email via SendGrid
      const msg = {
        to: options.to,
        from: {
          email: this.from,
          name: this.fromName,
        },
        replyTo: this.replyTo,
        subject: options.subject,
        html,
      };

      await sgMail.send(msg);

      this.logger.log(`Email sent successfully to ${options.to}: ${options.subject}`);
    } catch (error) {
      this.logger.error(`Failed to send email to ${options.to}:`, error);
      // Don't throw - email failures shouldn't break the app flow
    }
  }

  /**
   * Send verification email
   */
  async sendVerificationEmail(
    email: string,
    fullName: string,
    verificationToken: string,
  ): Promise<void> {
    const apiUrl = this.configService.get<string>('API_URL', 'http://localhost:3000');
    const verificationLink = `${apiUrl}/auth/verify-email?token=${verificationToken}`;

    await this.sendEmail({
      to: email,
      subject: 'Verify Your Email Address',
      template: 'verification-email',
      context: {
        fullName,
        verificationLink,
        expiresIn: '24 hours',
      },
    });
  }

  /**
   * Send password reset email
   */
  async sendPasswordResetEmail(
    email: string,
    fullName: string,
    resetToken: string,
  ): Promise<void> {
    const apiUrl = this.configService.get<string>('API_URL', 'http://localhost:3000');
    const resetLink = `${apiUrl}/auth/reset-password?token=${resetToken}`;

    await this.sendEmail({
      to: email,
      subject: 'Password Reset Request',
      template: 'password-reset',
      context: {
        fullName,
        resetLink,
        expiresIn: '1 hour',
      },
    });
  }

  /**
   * Send password changed confirmation email
   */
  async sendPasswordChangedEmail(email: string, fullName: string): Promise<void> {
    await this.sendEmail({
      to: email,
      subject: 'Your Password Has Been Changed',
      template: 'password-changed',
      context: {
        fullName,
        changedAt: new Date().toLocaleString('en-US', {
          dateStyle: 'long',
          timeStyle: 'short',
        }),
      },
    });
  }
}
