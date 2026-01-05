# Session Directions: Add Slack Bot Mode Support

## Context
The Socket Python CLI currently supports Slack notifications via incoming webhooks. We need to add an alternative "bot" mode that uses a Slack App with Bot Token for more flexible channel routing.

## Current Implementation
- File: `socketsecurity/plugins/slack.py`
- File: `socketsecurity/config.py`
- Env var: `SOCKET_SLACK_CONFIG_JSON`
- Current config uses `url` and `url_configs` for webhook routing

## Requirements

### 1. Add Mode Selection
- Add top-level `mode` field to Slack config
- Valid values: "webhook" (default), "bot"
- Mode determines which authentication and routing method to use

### 2. Webhook Mode (existing, default)
```json
{
  "enabled": true,
  "mode": "webhook",
  "url": ["https://hooks.slack.com/..."],
  "url_configs": {
    "webhook_0": {"repos": ["repo1"], "severities": ["critical"]}
  }
}
```
Keep all existing webhook functionality unchanged.

### 3. Bot Mode (new)
```json
{
  "enabled": true,
  "mode": "bot",
  "bot_configs": [
    {
      "name": "critical_alerts",
      "channels": ["security-alerts", "critical-incidents"],
      "repos": ["prod-app"],
      "severities": ["critical"],
      "reachability_alerts_only": true
    },
    {
      "name": "all_alerts", 
      "channels": ["dev-alerts"],
      "severities": ["high", "medium"]
    }
  ]
}
```

- New env var: `SOCKET_SLACK_BOT_TOKEN` (Bot User OAuth Token starting with `xoxb-`)
- Use `bot_configs` array instead of `url` + `url_configs`
- Each bot_config has:
  - `name`: identifier for logging
  - `channels`: array of Slack channel names or IDs to post to
  - All existing filter options: `repos`, `severities`, `alert_types`, `reachability_alerts_only`, `always_send_reachability`

### 4. Channel Routing
- Slack API accepts both channel names (without #) and channel IDs (C1234567890)
- Recommend supporting both: try name first, fallback to ID if needed
- API endpoint: `https://slack.com/api/chat.postMessage`
- Request format:
```python
{
    "channel": "channel-name",  # or "C1234567890"
    "blocks": blocks
}
```
- Headers: `{"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json"}`

### 5. Implementation Tasks

#### config.py
- No changes needed (config is loaded from JSON env var)

#### slack.py
1. Update `send()` method:
   - Check `self.config.get("mode", "webhook")` 
   - If "webhook": call existing `_send_webhook_alerts()` (refactor current logic)
   - If "bot": call new `_send_bot_alerts()`

2. Create `_send_bot_alerts()` method:
   - Get bot token from env: `os.getenv("SOCKET_SLACK_BOT_TOKEN")`
   - Validate token exists and starts with "xoxb-"
   - Get `bot_configs` from config
   - For each bot_config, filter alerts same way as webhooks
   - For each channel in bot_config's channels array, post message via chat.postMessage API

3. Create `_post_to_slack_api()` helper method:
   - Takes bot_token, channel, blocks
   - Posts to https://slack.com/api/chat.postMessage
   - Returns response
   - Log errors with channel name/ID for debugging

4. Error handling:
   - Log if bot token missing when mode is "bot"
   - Handle API errors (invalid channel, missing permissions, rate limits)
   - Parse Slack API response JSON (it returns 200 with error in body)

5. Reuse existing:
   - All filtering logic (`_filter_alerts`)
   - All block building (`create_slack_blocks_from_diff`, `_create_reachability_slack_blocks_from_structured`)
   - All reachability data loading

### 6. Testing Considerations
- Test both modes don't interfere with each other
- Test channel name resolution
- Test channel ID usage
- Test multiple channels per bot_config
- Test error handling when bot token invalid or missing
- Verify block count limits still respected (50 blocks)

### 7. Documentation Updates (README.md)
Add bot mode configuration examples and SOCKET_SLACK_BOT_TOKEN env var documentation.

## Key Files to Modify
1. `socketsecurity/plugins/slack.py` - main implementation
2. `README.md` - add bot mode documentation

## Notes
- Slack chat.postMessage returns HTTP 200 even on errors. Check response JSON for `"ok": false`
- Rate limit: 1 message per second per channel (more generous than webhooks)
- Channel names are case-insensitive, don't need # prefix
- Public and private channels both work if bot is invited
