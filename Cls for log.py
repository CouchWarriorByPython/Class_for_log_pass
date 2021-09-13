import uuid
import hashlib
import psycopg2


class Registration:
    """Класс для регистрации пользователя"""
    def __init__(self, login, password, check_pass):
        self.login = login
        self.password = password
        self.check_pass = check_pass
        self.__len_password()
        self.__hash_password_and_login()
        self.__check_password()

    def __len_password(self):
        if len(self.password) < 8:
            raise ValueError("The password is too short")

    def __hash_password_and_login(self):
        self.salt = uuid.uuid4().hex
        self.login = hashlib.sha256(self.login.encode()).hexdigest()
        self.password = hashlib.sha256(self.salt.encode() + self.password.encode()).hexdigest() + ':' + self.salt

    def __check_password(self):
        password, salt = self.password.split(':')
        if password == hashlib.sha256(salt.encode() + self.check_pass.encode()).hexdigest():
            print('Passwords match')
            self.data = [self.login, password, salt]
        else:
            print("Passwords do not match")


class ConnectToDB:
    """Класс для подкючения к Базе данных"""
    def __init__(self, host='localhost', user='postgres', password='123321', db_name='Users_data'):
        self.host = host
        self.user = user
        self.password = password
        self.db_name = db_name
        self.__connect()

    def __connect(self):
        try:
            self.connection = psycopg2.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.db_name
            )
            self.connection.autocommit = True
            print(f"Connection to DB {self.db_name} successful")

        except Exception as ex:
            print('[INFO] Error while working with PostgresSQL', ex)

    def write_data_to_db(self, data):
        login, password, salt = data
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(
                    f"INSERT INTO users (login, hash_pass, salt) "
                    f"VALUES ('{login}', '{password}', '{salt}');"
                )

                print('[INFO] Data was successfully inserted')

        except Exception as ex:
            print('[INFO] Error while working with PostgresSQL', ex)

        finally:
            if self.connection:
                self.connection.close()
                print('[INFO] PostgresSQL connection closed')

    def check_data_to_db(self, login, password):
        try:
            login_hash = hashlib.sha256(login.encode()).hexdigest()
            with self.connection.cursor() as cursor:
                cursor.execute(
                    f"SELECT salt FROM users WHERE login = '{login_hash}';"
                )
                get_salt = cursor.fetchone()
                password_hash = hashlib.sha256(''.join(get_salt).encode() + password.encode()).hexdigest()
                cursor.execute(
                    f"SELECT salt FROM users WHERE login = '{login_hash}' AND hash_pass = '{password_hash}';"
                )
            print('[INFO] Congratulations, you have entered')

        except Exception as ex:
            print('[INFO] Error while working with PostgresSQL', ex)

        finally:
            if self.connection:
                self.connection.close()
                print('[INFO] PostgresSQL connection closed')


name = input('Enter your name: ')
password_user = input('Enter your password: ')
check_conf_pass = input('Enter the password again to confirm: ')
check = Registration(name, password_user, check_conf_pass)
db = ConnectToDB()
db.write_data_to_db(check.data)
aut = input('Enter your name: ')
pass_aut = input('Enter your password: ')
db = ConnectToDB()
db.check_data_to_db(aut, pass_aut)

