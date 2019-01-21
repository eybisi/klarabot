import telegram
from telegram.ext import Updater, CommandHandler, Filters, MessageHandler, DispatcherHandlerStop
import requests
import json
import threading
import time
import yara
import re
from bs4 import BeautifulSoup

config = json.loads(open("config.json").read())

TOKEN = config['TOKEN']
Klara_API = config['KlaraAPIKEY']
whitelist = config['whitelist']

Klara_API_URL = "http://127.0.0.1/index.php/api/jobs/"



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

def safe_send_message(bot,update,m):

    msgs = [m[i:i + 4096] for i in range(0, len(m), 4096)]
    for text in msgs:
        try:
            bot.send_message(update.message.chat_id,text)
        except Exception as e:
            print(e)

def add_yara(bot, update):

    msg = update.message.text.split(" ",1)
    if len(msg) != 2:
        bot.send_message(update.message.chat_id,'1 parameter pls')

    if msg[1].startswith('rule'):
        try:
            yara.compile(source=msg[1])
        except Exception as e:
            bot.send_message(update.message.chat_id,'Err : {}'.format(e))
            return

        bot.send_message(update.message.chat_id,'Rule is succesfully added to list !')
        rules.append(msg[1])
        save_yara()

    elif msg[1].startswith('https://github.com'):
        ## parse each rule. example : https://github.com/Neo23x0/signature-base/tree/master/yara
        print('parse')
        r = requests.get(msg[1])
        if r.ok:
            soup = BeautifulSoup(r.text,'html.parser')

            link_list = []
            for div in soup.findAll('table',{'class':'files'}):
                for row in div.findAll('tr'):
                    for cont in row.findAll('td',{'class':'content'}):
                        for span in cont.findAll('span'):
                            for a in span.findAll('a'):
                                href = a.get('href')
                                href = href.replace('/blob','')
                                link_list.append('https://raw.githubusercontent.com'+href)

            for link in link_list:
                r = requests.get(link)
                if r.ok:
                    print(link + ' added')
                    try:
                        yara.compile(source=r.text)
                    except Exception as e:
                        bot.send_message(update.message.chat_id,'Err : {}\nNot adding rule {}'.format(e,link))
                        continue

                    rules.append(r.text)

                else:
                    print('bad link')

            save_yara()
        else:
            print('bad request')

    elif msg[1].startswith('https://raw.githubusercontent.com'):
        ## add only one rule
        r = requests.get(msg[1])
        if r.ok:
            print(r.text)
            try:
                yara.compile(source=r.text)
            except Exception as e:
                bot.send_message(update.message.chat_id,'Err : {}'.format(e))
                return

            rules.append(r.text)

        else:
            print('bad request')

    else:
        bot.send_message(update.message.chat_id,'Bad parameter')


def list_yara(bot, update):
    msg = update.message.text.split(' ')
    if len(msg) == 1:
        rulecount = 1
        m =''
        for rule in rules:
            try:
                first_rule = re.search('rule (\w+).*\n?{',rule)
            except Exception as e:
                bot.send_message(update.message.chat_id,e)
                continue
            if first_rule:
		m += '{} {}\n'.format(rulecount,first_rule.group(0))
	    else:
                m += '{} {}\n'.format(rulecount,'Empty rule')

            rulecount +=1

        if m != '':
            bot.send_message(update.message.chat_id,len(rules))
            safe_send_message(bot,update,m)

        else:
            bot.send_message(update.message.chat_id,'Empty')


    elif msg[1].isdigit():
        ind = int(msg[1])
        if ind-1 < len(rules):
            safe_send_message(bot,update,rules[ind-1])

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
	    save_yara()
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
    print(len(data['rules']))
    r = requests.post(Klara_API_URL+"add", data=data)
    if r.ok:
        j = json.loads(r.text)
        print(r.text)
        print(j['return_data'])
        bot.send_message(chat_id, "[+] Success: Job Id: " +str(j['return_data'][0]))
    else:
	bot.send_message(chat_id,r.text)

def scan(bot, update):

    msg = update.message.text.split(' ')
    if len(msg) != 2:
        bot.send_message(update.message.chat_id,'Please give repo number. Type /list_repos if you dont know. Example usage /scan 1 ')
        return
    scan_internal(update.message.chat_id)

def list_repos(bot, update):
    data = {"auth_code":Klara_API}
    print(data)
    r = requests.post(Klara_API_URL+"get_allowed_repos", data=data)
    print(r.text)
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
	else :
	    bot.send_message(update.message.chat_id,r.text)


def status_job(bot, update):
    	jobid = update.message.text.split(" ", 1)[1]
	if not jobid.isdigit():
		bot.send_message(update.message.chat_id,  " Bad integer")
	data = {"auth_code":Klara_API, "detailed_info":"true"}
	r = requests.post(Klara_API_URL+"status/"+jobid, data=data)
	j = json.loads(r.text)
	if r.ok:
	    rd = j['return_data']
	    if rd['status'] != 'finished':
		mes = "Status : " + rd['status']
		mes += "\n###############\n"
		mes += "Mail : " + rd['description']['notify_email']
		mes += "\n###############\n"
		mes += "Start time : " + rd['start_time']
		mes += "\n###############\n"
		mes += "Owner : " + rd['owner']
		bot.send_message(update.message.chat_id, mes)
	    else:

		try: 	
			mes = "Status : " + rd['status']
			mes += "\n###############\n"
				
			mes += "Matched Files: \n"+ rd['matched_files']
			mes += "\n###############\n"
			
			mes += "Execution time : " + str(rd['description']['execution_time'])	
			mes += "\nStart time : " + rd['start_time']
			mes += "\nFinish time : " + rd['finish_time']
			mes += "\n###############\n"
			mes += "\nNotify email : " + rd['description']['notify_email']
		except Exception as e:
			print(e)
				
		if rd['description']['yara_warnings'] != "false":
			mes += "\nYara warning : " + rd['description']['yara_warnings']
		
		if rd['description']['yara_errors'] != "false":
			mes += "\nYara error : " + rd['description']['yara_errors']
		
		safe_send_message(bot,update,mes)
		yara_rules = rd['rules']
		f = open("/tmp/rules.txt","w")
		f.write(yara_rules)
		f.close()
		f = open("/tmp/rules.txt","r")
		bot.send_document(update.message.chat_id, document=f)
		f.close()

		results = rd['results']
		f = open("/tmp/results.txt","w")
		f.write(results)
		f.close()
		f = open("/tmp/results.txt","r")
		bot.send_document(update.message.chat_id,document=f)
		f.close()

def chat_id(bot, update):
    bot.send_message(update.message.chat_id, update.message.chat_id)

def _help(bot, update):
    m = "/add_yara rule\n"\
        "/list_yara | /list_yara 1 | /list_yara detail\n"\
        "/remove_yara 1 | /remove_yara 1 2 3\n"\
        "/scan\n"\
        "/start_autoscan | /start_autoscan 3600 . 2nd argument is in seconds\n"\
        "/stop_autoscan\n"\
        "/is_autoscan_running\n"\
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
	self.first_run()
	
    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args,  **self.kwargs)

    def first_run(self):
        fr = threading.Thread(target=self.function,args=self.args)
        fr.start()

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
        bot.send_message(whitelist[0],'Unknown user: {}'.format(update.message.from_user))
  	raise DispatcherHandlerStop

if __name__ == "__main__":

    add_handler = CommandHandler('add_yara', add_yara)
    list_handler = CommandHandler('list_yara', list_yara)
    remove_handler = CommandHandler('remove_yara', remove_yara)
    scan_handler = CommandHandler('scan', scan)
    list_rep_handler = CommandHandler('list_repos', list_repos)
    list_jobs_handler = CommandHandler('list_jobs', list_jobs)
    del_handler = CommandHandler('delete_job', delete_job)
    status_handler = CommandHandler('status_job', status_job)
    chat_handler = CommandHandler('chat_id1', chat_id)
    start_auto_handler = CommandHandler('start_autoscan', start_autoscan)
    stop_auto_handler = CommandHandler('stop_autoscan', stop_autoscan)
    is_auto_handler = CommandHandler('is_autoscan_running', is_autoscan_running)

    load_yara()
    help_handler = CommandHandler('help1', _help)
    rt = repeatafterme(60*60*12, scan_internal, whitelist[1])
    dispatcher.add_handler(MessageHandler(Filters.all, check_allowed), -1)
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
