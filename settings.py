import json
import getpass  # For secure input of sensitive data

limit_file = 'settings/limits.json'
telegram_file = 'settings/telegram.json'

def load_settings(file, data):
    with open(file, 'w') as f:
        json.dump(data, f, indent=2)

def settings():
    print(''' 
          [1] SET TELEGRAM DETAILS
          [2] EXIT
    ''')

    choice = input('[ ~ ] Enter your choice: ').strip()

    if choice == '1':  # Fix string comparison
        print('Set Telegram Details')
        telegram_id = input('[ ~ ] Enter your Chat ID Or Channel ID: ').strip()

        # Using getpass for sensitive input
        telegram_token = getpass.getpass('[ ~ ] Enter your Telegram Token: ').strip()

        data = {'chat_id': telegram_id, 'bot_token': telegram_token}
        load_settings(telegram_file, data)
        print("Telegram details saved successfully.")

    elif choice == '2':
        print("Exiting...")
        exit()
    else:
        print("Invalid choice. Please try again.")
