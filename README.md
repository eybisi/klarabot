# klarabot
Telegram Bot to use [KLaRa](https://github.com/KasperskyLab/klara) remotely . Can be combined with [vtfeeder](https://github.com/eybisi/vtfeeder) . Vtfeeder downloads file feed from virustotal each hour and klara scans files automatically.


# Setup

To use klara's API you need to first create one api key and put it on your desired account in database. I used admin acc for this purpose you can use other accounts.

To add new key to database simply run this query while you are in mysql.

`update users set api_auth_code='testAPICode', api_perms='["all"]' , api_status='1' where username='admin'`

Put your APIKEY inside of [config.json](config.json) and replace with "KLARA_API_KEY" 

Next create telegram bot. Simply go to [t.me/botfather](t.me/botfather) and type /newbot . Give name and username to your bot. Then take HTTP API token and put in [config.json](config.json) and replace with "TELEGRAM_BOT_TOKEN" 


# Whitelist

Since you dont want to let other people to use your internal system, I created some auth with chat_id. See this [line](https://github.com/eybisi/klarabot/blob/master/klara.py#L274) in my code. When you first run bot type /chat_id . Put that number 
to 'whitelist' list variable in [config.json](config.json) . Uncomment [line](https://github.com/eybisi/klarabot/blob/master/klara.py#L274) and [line](https://github.com/eybisi/klarabot/blob/master/klara.py#L258) you are good to go. If you want another person to use bot, simply follow this procedure again. 


# Commands

### /add_yara :
Add new yara rule to ruleset. While sending new job to KLaRa, bot will use these yara rules. If your yara rule have some syntax error in it, bot will respond these errors.
```
/add_yara rule ExampleRule
{
    strings:
        $my_text_string = "text here"
        $my_hex_string = { E2 34 A1 C8 23 FB }

    condition:
        $my_text_string or $my_hex_string
}
```

### /list_yara :
List yara rules. `/list_yara` will list rules with just rule names. `/list_yara 1` will list rule[0] with full info. `/list_yara detail` will list all rules with full info.

### /remove_yara :
Remove yara rule from yara list. You can give multiple indexes. 

`/remove_yara 1 `

`/remove_yara 1 2 3`

### /scan :
Send new scan job to klara with all rules combined. Curently it will scan repository 1. 

`/scan`

### /list_repos
List repositories that are defined in database.

`/list_repos`

### /list_jobs
List all jobs. Finished or currently running

`/list_jobs`

### /delete_job
Delete job with given id. You can get job id with `/list_jobs` command.

`/delete_job 42`

### /status_job
Get info about job with given id. 

`/status_job 42`

### /start_autoscan 
Start autoscan. Bot will send new scan jobs to klara each x seconds. Default is 60\*60\*12 .

`/start_autoscan`

`/start_autoscan 3600`

### /stop_autoscan
Stop autoscan. 

`/stop_autoscan`

### /is_autoscan_running
Returns if autoscan on. If it is on bot will send next call in seconds

`/is_autoscan_running`

