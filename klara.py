import telegram
from telegram.ext import Updater, CommandHandler, Filters, MessageHandler, DispatcherHandlerStop
import requests
import json
import config
import threading
import time
import yara
import re


TOKEN = config.TOKEN
Klara_API = config.KlaraAPIKEY
Klara_API_URL = "http://127.0.0.1/index.php/api/jobs/"
whitelist = config.whitelist


updater = Updater(token=TOKEN)
bot = telegram.Bot(token=TOKEN)
dispatcher = updater.dispatcher

rules = []

def save_yara():
    try:
        f = open('yara_rules.txt', 'w')
    except Exception as err:
        raise err
    json.dump(rules, f)
    f.close()

def load_yara():
    global rules
    try:
        f = open('yara_rules.txt', 'r')
    except Exception as err:
        raise err
    rules = json.load(f)

def add_yara(bot, update):
    yr = update.message.text.split(" ", 1)[1]
    try:
        yara.compile(source=yr)
    except Exception as e:
        bot.send_message(update.message.chat_id,'Err : {}'.format(e))
        return

    bot.send_message(update.message.chat_id,'Rule is succesfully added to list !')
    rules.append(yr)
    save_yara()


def list_yara(bot, update):
    msg = update.message.text.split(' ')
    if len(msg) == 1:
        matches = re.findall('rule (\w+)','\n'.join(rules))
        m = ''
        for c,r in enumerate(matches):
            m += '{} {}\n'.format(c+1,r)

        if m != '':
            bot.send_message(update.message.chat_id, m)
        else:
            bot.send_message(update.message.chat_id,'Empty')
    elif msg[1] == 'detail':
        r = "\n".join(rules)
        bot.send_message(update.message.chat_id, r)

    elif msg[1].isdigit():
        ind = int(msg[1])
        if ind-1 < len(rules):
            bot.send_message(update.message.chat_id,rules[ind-1])

        else:
            bot.send_message(update.message.chat_id,'Index is greater than length of rules list')

    else:
        bot.send_message(update.message.chat_id,'bad syntax')

def remove_yara(bot, update):
    msg = update.message.text.split(' ')
    if len(rules) == 0:
        bot.send_message(update.message.chat_id,'There is no rule to delete, first add one')

    if len(msg) < 2:
        bot.send_message(update.message.chat_id,'Send me indexes of rules that you want to delete')
        return
    msg = msg[1:]
    for i in msg:
        if not i.isdigit() or int(i)-1 >= len(rules) or int(i) < 1:
            bot.send_message(update.message.chat_id,'I said indexes')
            return

    ##sort reverse order
    indexes = [ int(i) for i in msg]
    indexes.reverse()
    for i in indexes:
        try:
            ind = i-1
            del rules[ind]
        except:
            break
    else:
        bot.send_message(update.message.chat_id,'Success given indexes are deleted')

#
def scan_internal(chat_id):
    all_rules = '\n'.join(rules)
    try:
        yara.compile(source=all_rules)
    except Exception as e:
        bot.send_message(chat_id,'Err : {}'.format(e))
        return
    ##Can take repo id as input
    data = {"auth_code":Klara_API, "rules": "\n".join(rules), "repositories":'["1"]'}
    r = requests.post(Klara_API_URL+"add", data=data)
    if r.ok:
        j = json.loads(r.text)
        print(j['return_data'])
        bot.send_message(chat_id, "[+] Success: Job Id: " +str(j['return_data'][0]))


def scan(bot, update):

    msg = update.message.text.split(' ')
    if len(msg) != 2:
        bot.send_message(update.message.chat_id,'Please give repo number. Type /list_repos if you dont know. Example usage /scan 1 ')
        return
    scan_internal(update.message.chat_id)

def list_repos(bot, update):
    data = {"auth_code":Klara_API}
    r = requests.post(Klara_API_URL+"get_allowed_repos", data=data)
    j = json.loads(r.text)
    mes = "Repositories: \n"
    for i in j['return_data']:
        mes += i['entry'] + " "+ i['id'] +"\n"
        bot.send_message(update.message.chat_id, mes)


def list_jobs(bot, update):
    data = {"auth_code":Klara_API}
    r = requests.post(Klara_API_URL+"get_all_jobs", data=data)
    j = json.loads(r.text)
    mes = "List of Jobs:\n"
    for i in j['return_data']:
        mes += "ID: "+ i['id'] + " Status: " + i['status']+ " Rule: "+i['rules_first_line'] +"\n"
        bot.send_message(update.message.chat_id, mes)

def delete_job(bot, update):
    jobid = update.message.text.split(" ", 1)[1]
    if not jobid.isdigit():
        bot.send_message(update.message.chat_id,  " Bad integer")
        data = {"auth_code":Klara_API}
        r = requests.post(Klara_API_URL+"delete/"+jobid, data=data)
        if r.ok:
            bot.send_message(update.message.chat_id, "[+] "+jobid+" deleted")

def status_job(bot, update):
    jobid = update.message.text.split(" ", 1)[1]
    if not jobid.isdigit():
        bot.send_message(update.message.chat_id,  " Bad integer")
        data = {"auth_code":Klara_API, "detailed_info":"true"}
        r = requests.post(Klara_API_URL+"status/"+jobid, data=data)
        j = json.loads(r.text)
        if r.ok:
            rd = j['return_data']
            if rd['status'] == 'new':
                bot.send_message(update.message.chat_id, "Status "+rd['status'])
            else:
                mes = "Status : " + rd['status']
                mes += "\n###############\n"
                mes += "Rule: \n" + rd['rules']
                mes += "\n###############\n"
                mes += "Matched Files: \n"+ rd['matched_files']
                mes += "\n###############\n"
                mes += "Results: \n" + rd['results']
                mes += "\n###############\n"
                hashes = "\n".join(rd['hashes'])
                mes += "Hashes: \n" + hashes
                bot.send_message(update.message.chat_id, mes)

def chat_id(bot, update):
    bot.send_message(update.message.chat_id, update.message.chat_id)

def _help(bot, update):
    m = "/add_yara rule\n"\
        "/list_yara | /list_yara 1 | /list_yara detail\n"\
        "/remove_yara 1 | /remove_yara 1 2 3\n"\
        "/scan\n"\
        "/start_autoscan | /start_autoscan 3600 . 2nd argument is in seconds\n"\
        "/stop_autoscan\n"\
        "/is_autoscan_running"\
        "/list_repos\n"\
        "/list_jobs\n"\
        "/delete_job 42\n"\
        "/status_job 42\n"

    try:
        bot.send_message(update.message.chat_id, m)
    except Exception as e:
        print(e)

def start_autoscan(bot, update):
    msg = update.message.text.split(' ')
    if len(msg) == 2:
        if msg[1].isdigit():
            rt.change_interval(int(msg[1]))

    rt.start()
    bot.send_message(update.message.chat_id, 'Looper started')

def stop_autoscan(bot, update):
    rt.stop()
    bot.send_message(update.message.chat_id, 'Looper stopped')

def is_autoscan_running(bot, update):
    bot.send_message(update.message.chat_id, '? Looper is running : {}'.format(rt.is_running))
    if rt.is_running:
        time_c = rt.next_call - time.time()
        bot.send_message(update.message.chat_id, 'next call in {} seconds'.format(int(time_c)))

class repeatafterme(object):
    def __init__(self,  interval,  function,  *args,  **kwargs):
        self._timer = None
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.is_running = False
        self.next_call = time.time()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args,  **self.kwargs)

    def start(self):
        if not self.is_running:
            self.next_call += self.interval
            self._timer = threading.Timer(self.next_call - time.time(),  self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False

    def change_interval(self,new_time):
        self.interval = new_time

def check_allowed(bot, update):
    if update.message.chat_id not in whitelist:
        bot.send_message(whitelist[0],'Unknown user')

if __name__ == "__main__":

    #rt = repeatafterme(60*60*12, scan_internal, whitelist[0])
    add_handler = CommandHandler('add_yara', add_yara)
    list_handler = CommandHandler('list_yara', list_yara)
    remove_handler = CommandHandler('remove_yara', remove_yara)
    scan_handler = CommandHandler('scan', scan)
    list_rep_handler = CommandHandler('list_repos', list_repos)
    list_jobs_handler = CommandHandler('list_jobs', list_jobs)
    del_handler = CommandHandler('delete_job', delete_job)
    status_handler = CommandHandler('status_job', status_job)
    chat_handler = CommandHandler('chat_id', chat_id)
    start_auto_handler = CommandHandler('start_autoscan', start_autoscan)
    stop_auto_handler = CommandHandler('stop_autoscan', stop_autoscan)
    is_auto_handler = CommandHandler('is_autoscan_running', is_autoscan_running)

    load_yara()
    help_handler = CommandHandler('help', _help)
    #dispatcher.add_handler(MessageHandler(Filters.all, check_allowed), -1)
    dispatcher.add_handler(add_handler)
    dispatcher.add_handler(list_handler)
    dispatcher.add_handler(remove_handler)
    dispatcher.add_handler(scan_handler)
    dispatcher.add_handler(list_rep_handler)
    dispatcher.add_handler(list_jobs_handler)
    dispatcher.add_handler(del_handler)
    dispatcher.add_handler(status_handler)
    dispatcher.add_handler(chat_handler)
    dispatcher.add_handler(help_handler)
    dispatcher.add_handler(start_auto_handler)
    dispatcher.add_handler(stop_auto_handler)
    dispatcher.add_handler(is_auto_handler)

    updater.start_polling()
