# API templates for secure_request

`add` = the command the **user** runs once to store the key. `request` = what the agent sends.

## OpenAI
add: `secretsafe add openai --host api.openai.com --header "Authorization: Bearer {{secret}}"`
request: `POST https://api.openai.com/v1/chat/completions` — no placeholder needed (default injection).

## Anthropic
add: `secretsafe add anthropic --host api.anthropic.com --header "x-api-key: {{secret}}"`
request: `POST https://api.anthropic.com/v1/messages`, headers `anthropic-version: 2023-06-01`, `content-type: application/json`.

## GitHub
add: `secretsafe add github --host api.github.com --header "Authorization: Bearer {{secret}}"`
request: `GET https://api.github.com/user`, header `Accept: application/vnd.github+json`.

## Google Gemini
add: `secretsafe add gemini --host generativelanguage.googleapis.com --query key`
request: `POST https://generativelanguage.googleapis.com/v1beta/models/<model>:generateContent` — key goes into `?key=` automatically.

## Stripe
add: `secretsafe add stripe --host api.stripe.com --header "Authorization: Bearer {{secret}}"`
request: `GET https://api.stripe.com/v1/balance`. Form bodies: `Content-Type: application/x-www-form-urlencoded`, body `amount=1000&currency=eur`.
Use a **test-mode** key unless the user explicitly wants live mode, and confirm any charge before sending it.

## Hugging Face
add: `secretsafe add huggingface --host api-inference.huggingface.co --host huggingface.co --header "Authorization: Bearer {{secret}}"`

## Notion
add: `secretsafe add notion --host api.notion.com --header "Authorization: Bearer {{secret}}"`
request headers: `Notion-Version: 2022-06-28`.

## Slack (bot token)
add: `secretsafe add slack --host slack.com --header "Authorization: Bearer {{secret}}"`
request: `POST https://slack.com/api/chat.postMessage` — confirm with the user before sending any message.

## Telegram bot
The token is part of the URL **path**, which SecretSafe forbids for placeholders. Use a proxy or an API that accepts the token in a header instead; do not ask the user for the token.

## Generic
- Bearer: `--header "Authorization: Bearer {{secret}}"`
- Header key: `--header "X-API-Key: {{secret}}"`
- Query key: `--query api_key`
- Basic auth: store the already base64-encoded `user:pass` and use `--header "Authorization: Basic {{secret}}"`
