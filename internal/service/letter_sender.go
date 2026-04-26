package service

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"

	"auth-service/internal/config"
)

const yandexPostboxEndpoint = "https://postbox.cloud.yandex.net"

// LetterSender отправляет письма через Yandex Postbox (SES v2-совместимый API).
type LetterSender struct {
	client *sesv2.Client
	sender string
}

// NewLetterSender создаёт клиент SES v2 с кастомным endpoint Yandex Postbox.
func NewLetterSender(cfg *config.Config) (*LetterSender, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(
		context.Background(),
		awsconfig.WithRegion(cfg.AWSRegion),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				cfg.AWSAccesKeyID,
				cfg.AWSSecretAccessKEY,
				"",
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	client := sesv2.NewFromConfig(awsCfg, func(o *sesv2.Options) {
		o.BaseEndpoint = aws.String(yandexPostboxEndpoint)
	})

	return &LetterSender{
		client: client,
		sender: cfg.PostboxSender,
	}, nil
}

// SendVerificationCode отправляет письмо с кодом подтверждения.
func (l *LetterSender) SendVerificationCode(ctx context.Context, toEmail, code string) error {
	subject := "Ваш код подтверждения"
	textBody := fmt.Sprintf("Ваш код подтверждения: %s\n\nЕсли вы не запрашивали код — проигнорируйте это письмо.", code)
	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px">
  <h2 style="margin-bottom:8px">Код подтверждения</h2>
  <p style="color:#555">Введите этот код для входа:</p>
  <div style="font-size:36px;font-weight:bold;letter-spacing:8px;padding:16px 0;color:#1a1a1a">%s</div>
  <p style="color:#888;font-size:13px">Если вы не запрашивали код — проигнорируйте это письмо.</p>
</body>
</html>`, code)

	return l.sendEmail(ctx, toEmail, subject, textBody, htmlBody)
}

// sendEmail — базовый метод отправки письма с текстовым и HTML-телом.
func (l *LetterSender) sendEmail(ctx context.Context, to, subject, textBody, htmlBody string) error {
	input := &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(l.sender),
		Destination: &types.Destination{
			ToAddresses: []string{to},
		},
		Content: &types.EmailContent{
			Simple: &types.Message{
				Subject: &types.Content{
					Data:    aws.String(subject),
					Charset: aws.String("UTF-8"),
				},
				Body: &types.Body{
					Text: &types.Content{
						Data:    aws.String(textBody),
						Charset: aws.String("UTF-8"),
					},
					Html: &types.Content{
						Data:    aws.String(htmlBody),
						Charset: aws.String("UTF-8"),
					},
				},
			},
		},
	}

	if _, err := l.client.SendEmail(ctx, input); err != nil {
		return fmt.Errorf("sesv2 send email to %s: %w", to, err)
	}
	return nil
}
