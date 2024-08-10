import logging
import logging.config
import re
import paramiko
import yaml
import os
import psycopg2

from yaml.loader import SafeLoader
from telegram import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, ConversationHandler

MESS_MAX_LENGTH=4096

def config():

    if not os.path.exists('log'):
        os.mkdir('log')
    
    script_dir = os.path.abspath(os.path.dirname(__file__))

    global conf_values 
    conf_values = yaml.load(open(os.path.join(script_dir,'bot.conf'), 'r'), Loader=SafeLoader)

    LOGGING_CONFIG = {
        "version": 1,
        "formatters": { 
            "default": {
                "format": "%(asctime)s \t %(levelname)s:%(name)s: %(message)s",
            },
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "level": conf_values.get('log_level'),
                "class": "logging.handlers.RotatingFileHandler",
                "filename": os.path.join(conf_values.get('path'),'logfile.log'),
                "maxBytes": conf_values.get('max_log_size')*1024,
                "backupCount": conf_values.get('max_log_files')-1,
            },
        },
        "loggers": { },
            "root": { 
                "level": conf_values.get('log_level'),
                "handlers": [
                    "default",
                ],
            },
        }

    logging.config.dictConfig(LOGGING_CONFIG)

def initializationTables():

    connection = psycopg2.connect(dbname="tg_bot", user="user", password="password", host="192.168.162.130", port=5432)
    connection.autocommit=True

    cur = connection.cursor()
    
    cur.execute('''CREATE TABLE IF NOT EXISTS emails (\
                ID serial PRIMARY KEY,\
                email varchar(256) NOT NULL)''')
    
    cur.execute('''CREATE TABLE IF NOT EXISTS phones (\
            ID serial PRIMARY KEY,\
            phone varchar(20) NOT NULL)''')

    connection.close()

def initializationDatabase():

    connection = psycopg2.connect(user="user", password="password", host="192.168.162.130", port=5432)
    connection.autocommit=True

    cur = connection.cursor()

    cur.execute('''SELECT datname FROM pg_database''')
    res = cur.fetchall()

    if "tg_bot" not in res:
        cur.execute('''CREATE DATABASE tg_bot''')

    initializationTables()

    connection.close()

def insertIntoEmailsTable(email):

    connection = psycopg2.connect(dbname="tg_bot", user="user", password="password", host="192.168.162.130", port=6666)
    connection.autocommit=True
    cur = connection.cursor()

    cur.execute(f'''INSERT INTO emails (email) VALUES ({email})''')

    connection.close()

def insertIntoPhonesTable(phone):

    connection = psycopg2.connect(dbname="tg_bot", user="user", password="password", host="192.168.162.130", port=6666)
    connection.autocommit=True
    cur = connection.cursor()

    cur.execute(f'''INSERT INTO phones (phone) VALUES ('{phone}')''')

    connection.close()

def sshConnectAndExec(command):

    host = conf_values.get('host')
    user = conf_values.get('user')
    secret = conf_values.get('password')
    port = conf_values.get('port')

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=user, password=secret, port=port)
    stdin, stdout, stderr = client.exec_command(command)
    data = stdout.read() + stderr.read()
    data = str(data).replace('\\n', '\n').replace('\\t', '\t')[2:-1]
    client.close()

    return data

def start (update: Update, context):
    user = update.effective_user
    update.message.reply_text(f'Привет {user.full_name}!')

def echo (update: Update, context):
    update.message.reply_text("suck it, i will not be repeating for you")

def findPhoneNumbersCommand (update: Update, context):
    update.message.reply_text('Введите текст для поиска телефонных номеров: \n/stop чтобы остановить выполнение')
    return 'findPhoneNumbers'

def findPhoneNumbers (update: Update, context):

    user_input = update.message.text # Получаем текст, содержащий(или нет) номера телефонов

    # 8XXXXXXXXXX, 8(XXX)XXXXXXX, 8 XXX XXX XX XX, 8 (XXX) XXX XX XX, 8-XXX-XXX-XX-XX.
    phoneNumRegex = re.compile(r'((\+7|8)(\s)?(\(|\-)?\d{3}(\))?(\s|\-)?\d{3}(\s|\-)?\d{2}(\s|\-)?\d{2})')
    
    phoneNumberList = phoneNumRegex.findall(user_input) # Ищем номера телефонов

    if not phoneNumberList: # Обрабатываем случай, когда номеров телефонов нет
        update.message.reply_text('Телефонные номера не найдены')
        return ConversationHandler.END
    
    phoneNumbers = '' # Создаем строку, в которую будем записывать номера телефонов
    for i in range(len(phoneNumberList)):
        insertIntoPhonesTable(phoneNumberList[i][0])
        phoneNumbers += f'{i+1}. {phoneNumberList[i][0]}\n' # Записываем очередной номер
        
    update.message.reply_text(phoneNumbers) # Отправляем сообщение пользователю
    return ConversationHandler.END

def findEmailsCommand (update: Update, context):
    update.message.reply_text('Введите текст для поиска почтовых адресов: \n/stop чтобы остановить выполнение')
    return 'findEmails'

def findEmails (update: Update, context):

    user_input = update.message.text # Получаем текст, содержащий(или нет) почтовые адреса

    emailRegex = re.compile(r'\b[a-zA-Z0-9\.]*@{1}[a-zA-Z0-9\.]*\b')

    emailsList = emailRegex.findall(user_input) # Ищем почтовые адреса

    if not emailsList: # Обрабатываем случай, когда адресов нет
        update.message.reply_text('Почтовые адреса не найдены')
        return ConversationHandler.END # Завершаем выполнение функции
    
    emails = '' # Создаем строку, в которую будем записывать почтовые адреса
    for i in range(len(emailsList)):
        insertIntoEmailsTable(emailsList[i])
        emails += f'{i+1}. {emailsList[i]}\n' # Записываем очередной адрес
        
    update.message.reply_text(emails) # Отправляем сообщение пользователю
    return ConversationHandler.END

def verifyPasswordCommand (update: Update, context):
    update.message.reply_text('Введите пароль: \n/stop чтобы остановить выполнение')
    return 'verifyPassword'

def verifyPassword (update: Update, context):

    user_input = update.message.text # Получаем текст, содержащий(или нет) почтовые адреса

    passwordRegex = re.compile(r'(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[\!\@\#\$\%\^\&\*\(\)])[a-zA-Z0-9\!\@\#\$\%\^\&\*\(\)]{8,}')

    goodPasswordString = passwordRegex.findall(user_input) # Ищем почтовые адреса

    if not goodPasswordString: # Обрабатываем случай, когда адресов нет
        update.message.reply_text('Плохой пароль')
        return ConversationHandler.END # Завершаем выполнение функции

    update.message.reply_text(f'Пароль "{goodPasswordString[0]}" хороший!')
    return ConversationHandler.END

def getRelease (update: Update, context):
    update.message.reply_text(f'====== Release info ======\n\
        {sshConnectAndExec(command='hostnamectl')}')

def getUname (update: Update, context):
    update.message.reply_text(f'====== Host info ======\n\
        {sshConnectAndExec(command='uname -a')}')

def getUptime (update: Update, context):
    update.message.reply_text(f'====== Uptime info ======\n\
        {sshConnectAndExec(command='uptime')}')

def getDf (update: Update, context):
    update.message.reply_text(f'====== Disk space info ======\n\
        {sshConnectAndExec(command='df -h')}')

def getFree (update: Update, context):
    update.message.reply_text(f'====== Memory info ======\n\
        {sshConnectAndExec(command='free')}')

def getMpstat (update: Update, context):
    update.message.reply_text(f'====== Load info ======\n\
        {sshConnectAndExec(command='mpstat -A')}')

def getW (update: Update, context):
    update.message.reply_text(f'====== Active users ======\n\
        {sshConnectAndExec(command='w')}')

def getAuths (update: Update, context):
    update.message.reply_text(f'====== 10 last auth attempts ======\n\
        {sshConnectAndExec(command='\
            grep authentication /var/log/auth.log* | tail -n10 |\
            sed \'s/^.*acct="//g\' | sed \'s/".*$//g\' | sort | uniq -c | \
            awk \'{print $2 " account logged "  $1 " times"}\'')}')

def getCritical (update: Update, context):
    update.message.reply_text(f'====== 10 last critical events ======\n\
        {sshConnectAndExec(command='cat /var/log/syslog* | grep -P "(crit|CRIT)" | tail -n10')}')

def getPs (update: Update, context):
    data = f'====== Running processes info ======\n{sshConnectAndExec(command='ps -aux | sort -rk3')}'
    for x in range(0, len(data), MESS_MAX_LENGTH):
        mess = data[x: x + MESS_MAX_LENGTH]
        update.message.reply_text(mess)

def getSs (update: Update, context):
    data = f'====== Open ports info ======\n{sshConnectAndExec(command='ss')}'
    for x in range(0, len(data), MESS_MAX_LENGTH):
            mess = data[x: x + MESS_MAX_LENGTH]
            update.message.reply_text(mess)

def getAptList (update: Update, context):
    data = f'====== Installed packages ======\n{sshConnectAndExec(command='dpkg --list | grep -P "^(ii|rc)"')}'
    for x in range(0, len(data), MESS_MAX_LENGTH):
            mess = data[x: x + MESS_MAX_LENGTH]
            update.message.reply_text(mess)

def getServices (update: Update, context):
    data = f'====== Running processes ======\n{sshConnectAndExec(command='systemctl | grep active')}'
    for x in range(0, len(data), MESS_MAX_LENGTH):
                mess = data[x: x + MESS_MAX_LENGTH]
                update.message.reply_text(mess)

def help (update: Update, context):
    update.message.reply_text(\
'List of available commands:\n'+\
'/find_emails - поиск почтовых адресов в тексте\n'+\
'/find_phone_numbers - поиск телефонных номеров в тексте в форматах: '+\
'8XXXXXXXXXX, 8(XXX)XXXXXXX, 8 XXX XXX XX XX, 8 (XXX) XXX XX XX, 8-XXX-XXX-XX-XX\n'+\
'/verify_password - проверка пароля на сложность\n'+\
'/get_release - информация о релизе системы\n'+\
'/get_uname - информация об архитектуры процессора, имени хоста системы и версии ядра\n'+\
'/get_uptime - информация о времени работы системы\n'+\
'/get_df - информация о свободном дисковом пространстве\n'+\
'/get_free - информация о расходе опреативной памяти\n'+\
'/get_mpstat - информация о производительности системы\n'+\
'/get_w - информация о залогиненых пользователях\n'+\
'/get_auths - список УЗ, от имени которых выполнялось 10 последних авторизаций\n'+\
'/get_critical - 10 последних кртичных системных событий\n'+\
'/get_ps - информация о запущенных процессах\n'+\
'/get_ss - информация об открытых портах\n'+\
'/get_apt_list - информация об установленных пакетах\n'+\
'/get_services - информация о запущенных службах')

def main():

    #getting configuration
    config()
    token=conf_values.get('token')
    
    #creating db and tables if they do not exist
    initializationTables()
    initializationDatabase()

    #апдейтер тянет хуками сообщения из тг бота
    updater = Updater(token, use_context=True)

    #инициализирует обработчики
    dp = updater.dispatcher

    # Обработчики диалога
    convHandlerFindPhoneNumbers = ConversationHandler(
        entry_points=[CommandHandler('find_phone_numbers', findPhoneNumbersCommand)],
        states={
            'findPhoneNumbers': [MessageHandler(Filters.text & ~Filters.command, findPhoneNumbers)],
        },
        fallbacks=[]
    )

    convHandlerFindEmails = ConversationHandler(
        entry_points=[CommandHandler('find_emails', findEmailsCommand)],
        states={
            'findEmails': [MessageHandler(Filters.text & ~Filters.command, findEmails)],
        },
        fallbacks=[]
    )

    convHandlerVerifyPassword = ConversationHandler(
        entry_points=[CommandHandler('verify_password', verifyPasswordCommand)],
        states={
            'verifyPassword': [MessageHandler(Filters.text & ~Filters.command, verifyPassword)],
        },
        fallbacks=[]
    )

	#Регистрируем обработчики
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(convHandlerFindEmails)
    dp.add_handler(convHandlerFindPhoneNumbers)
    dp.add_handler(convHandlerVerifyPassword)
    dp.add_handler(CommandHandler("get_release", getRelease))
    dp.add_handler(CommandHandler("get_uname", getUname))
    dp.add_handler(CommandHandler("get_uptime", getUptime))
    dp.add_handler(CommandHandler("get_df", getDf))
    dp.add_handler(CommandHandler("get_free", getFree))
    dp.add_handler(CommandHandler("get_mpstat", getMpstat))
    dp.add_handler(CommandHandler("get_W", getW))
    dp.add_handler(CommandHandler("get_auths", getAuths))
    dp.add_handler(CommandHandler("get_critical", getCritical))
    dp.add_handler(CommandHandler("get_ps", getPs))
    dp.add_handler(CommandHandler("get_ss", getSs))
    dp.add_handler(CommandHandler("get_apt_list", getAptList))
    dp.add_handler(CommandHandler("get_services", getServices))
    dp.add_handler(CommandHandler("help", help))
                   
	# Регистрируем обработчик текстовых сообщений
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, echo))
		
	# Запускаем бота
    updater.start_polling()

	# Останавливаем бота при нажатии Ctrl+C
    updater.idle()

if __name__ == '__main__':
    main()