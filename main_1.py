from tkinter.ttk import Treeview
from tkinter import *
from tkinter import messagebox as mb
from random import randint
from os import path, getlogin
from hashlib import md5, sha512
from win32api import GetComputerName, GetWindowsDirectory, GetSystemMetrics, GetSystemDirectory
from winreg import *
import pickle

root = Tk()
user_info = {'login': None, 'password': None, 'limit': None, 'length': None}

def is_valid_password(password, length):
    if len(password) >= length or user_info['limit'] is False:
        return True

    return False

class WinGUI:
    def __init__(self):
        root.title("Лабораторная работа (1-3)")
        root.resizable(False, False)
        root.protocol("WM_DELETE_WINDOW", lambda: self.quit_app())

        self.menu = Menu(root)
        root.config(menu=self.menu)
        info = Menu(self.menu, tearoff=0)
        info.add_command(label="О програме", command=self.information)
        self.menu.add_cascade(label="Справка", menu=info)

    def information(self):
        mb.showinfo("Информация", "Автор: Абкеримов Эрвин\nГруппа: ФБ-73\nВариант: 1")

    def quit_app(self):
        root.destroy()

class WinPassword:
    def __init__(self, **kwargs):
        self.password = kwargs['value']
        self.len = kwargs['length']

    def change(self):
        label = Label(root, text="Изменение пароля", font=("Times new Roman", 30))
        label.pack()

        label_password1 = Label(root, text="Новый пароль:", font=("Times new Roman", 12))
        label_password1.place(x=20, y=76)
        entry_password1 = Entry(root, width=43, textvariable=StringVar(), show="*", relief=GROOVE, highlightthickness=1, font=("Times new Roman", 11))
        entry_password1.place(x=24, y=110)

        label_password2 = Label(root, text="Повторите пароль:", font=("Times new Roman", 12))
        label_password2.place(x=20, y=146)
        entry_password2 = Entry(root, width=43, textvariable=StringVar(), show="*", relief=GROOVE, highlightthickness=1, font=("Times new Roman", 11))
        entry_password2.place(x=24, y=180)

        button = Button(root, text="Изменить", font=("Times new Roman", 13), width=12, relief=GROOVE)
        button.config(command=lambda: self.command_change([label, label_password1, entry_password1, label_password2, entry_password2, button], [entry_password1.get(), entry_password2.get()]))
        button.place(x=230, y=250)

    def command_change(self, items, password):
        if password[0] == "":
            mb.showwarning("Внимание", "Введите, пожалуйста, новый пароль!")
            return

        if password[0] != password[1]:
            mb.showerror("Ошибка", "Новый пароль не совпадает с подтверждением!")
            return

        if password[0] == self.password:
            mb.showerror("Ошибка", "Новый пароль должен отличаться от старого!")
            return

        if is_valid_password(password[0], self.len) is False:
            mb.showerror("Ошибка", "Новый пароль должен содержать минимум {} симв.!".format(self.len))
            return

        global user_info
        password[0] += 'ErvinAbkerimov'
        password[0] = md5(password[0].encode()).hexdigest()
        user_info['password'] = password[0]
        try:
            with open('password.txt', 'rb') as f:
                file_load = pickle.load(f)

            data = dict(file_load)
            data[user_info['login']][0] = user_info['password']
        except:
            data = {user_info['login']: [user_info['password'], False, user_info['limit'], user_info['length']]}

        with open('password.txt', 'wb') as file:
            pickle.dump(data, file)

        if len(items) > 1:
            for i in items:
                i.destroy()

            WinPanel()
        else:
            mb.showinfo("Успешно", "Вы изменили пароль для входа в систему!")
            items[0].destroy()

class WinPanel:
    def __init__(self):
        self.admin = NORMAL if user_info['login'] == 'admin' else DISABLED
        self.main()

    def main(self):
        root.geometry("365x290")
        if self.admin == DISABLED:
            label = Label(root, text="Панель юзера", font=("Times new Roman", 28))
        else:
            label = Label(root, text="Панель администратора", font=("Times new Roman", 25))
        label.pack()

        button_change_pass = Button(root, text="Изменить пароль", relief=GROOVE, font=("Times new Roman", 12), width=34, command=ChildPassword)
        button_change_pass.place(x=24, y=70)

        button_list_users = Button(root, text="Список юзеров", relief=GROOVE, state=self.admin, font=("Times new Roman", 12), width=34, command=ChildListUsers)
        button_list_users.place(x=24, y=135)

        button_add_user = Button(root, text="Добавить юзера", relief=GROOVE, state=self.admin, font=("Times new Roman", 12), width=34, command=ChildAddUser)
        button_add_user.place(x=24, y=170)

        button_block_user = Button(root, text="Заблокировать юзера", relief=GROOVE, state=self.admin, font=("Times new Roman", 12), width=34, command=ChildBlockUser)
        button_block_user.place(x=24, y=205)

        button_limit_user = Button(root, text="Ограничение юзера", relief=GROOVE, state=self.admin, font=("Times new Roman", 12), width=34, command=ChildLimitUser)
        button_limit_user.place(x=24, y=240)

class ChildPassword(Toplevel):
    def __init__(self):
        Toplevel.__init__(self)
        self.title("Изменение пароля")
        self.geometry("354x160")
        self.resizable(False, False)
        self.child()

    def child(self):
        label_password1 = Label(self, text="Новый пароль:", font=("Times new Roman", 13))
        label_password1.place(x=20, y=10)
        entry_password1 = Entry(self, width=43, textvariable=StringVar(), show="*", font=("Times new Roman", 11))
        entry_password1.place(x=24, y=36)
        entry_password1.focus()

        label_password2 = Label(self, text="Повторите пароль:", font=("Times new Roman", 13))
        label_password2.place(x=20, y=60)
        entry_password2 = Entry(self, width=43, textvariable=StringVar(), show="*",  font=("Times new Roman", 11))
        entry_password2.place(x=24, y=86)

        button = Button(self, text="Принять", font=("Times new Roman", 12), width=12, relief=GROOVE,
                        command=lambda: WinPassword(value=user_info['password'], length=user_info['length']).command_change([self], [entry_password1.get(), entry_password2.get()]))
        button.place(x=215, y=120)

class ChildListUsers(Toplevel):
    def __init__(self):
        Toplevel.__init__(self)
        self.title("Список юзеров")
        self.resizable(False, False)
        self.child()

    def child(self):
        tree = Treeview(self, show="headings", selectmode="browse")
        headings = ['Логин', 'Блокировка', 'Ограничения', 'Мин. длина пароля']
        tree["columns"] = headings
        tree["displaycolumns"] = headings
        for h in headings:
            tree.heading(h, text=h, anchor=CENTER)
            tree.column(h, anchor=CENTER)

        with open('password.txt', 'rb') as f:
            file_load = pickle.load(f)

        data = dict(file_load)
        for login in file_load.keys():
            user_get = data.get(login)
            tree.insert('', END, values=tuple((login, user_get[1], user_get[2], user_get[3])))

        scroll_table = Scrollbar(self, command=tree.yview)
        tree.configure(yscrollcommand=scroll_table.set)
        scroll_table.pack(side=RIGHT, fill=Y)
        tree.pack(expand=YES, fill=BOTH)

class ChildAddUser(Toplevel):
    def __init__(self):
        Toplevel.__init__(self)
        self.title("Добавление юзера")
        self.geometry("354x110")
        self.resizable(False, False)
        self.child()

    def child(self):
        label_login = Label(self, text="Логин для входа:", font=("Times new Roman", 13))
        label_login.place(x=20, y=10)
        entry_login = Entry(self, width=43, textvariable=StringVar(), font=("Times new Roman", 11))
        entry_login.place(x=24, y=36)
        entry_login.focus()

        button = Button(self, text="Принять", font=("Times new Roman", 12), width=12, relief=GROOVE, command=lambda: self.command_AddUser(entry_login.get()))
        button.place(x=230, y=70)

    def command_AddUser(self, login):
        if len(login) < 4:
            mb.showwarning("Внимание", "Введите, пожалуйста, логин!")
            return

        with open('password.txt', 'rb') as f:
            file_load = pickle.load(f)

        data = dict(file_load)
        if data.get(login) is not None:
            mb.showerror("Ошибка", "Юзер с таким логином уже существует!")
            return

        data[login] = ['', False, True, randint(1, 9)]
        with open('password.txt', 'wb') as file:
            pickle.dump(data, file)

        mb.showinfo("Успешно", "Вы добавили нового юзера {}".format(login))
        self.destroy()

class ChildBlockUser(Toplevel):
    def __init__(self):
        Toplevel.__init__(self)
        self.title("Блокировка юзеров")
        self.resizable(False, False)
        self.child()

    def child(self):
        tree = Treeview(self, show="headings", selectmode="browse")
        headings = ['Логин', 'Блокировка']
        tree["columns"] = headings
        tree["displaycolumns"] = headings
        for h in headings:
            tree.heading(h, text=h, anchor=CENTER)
            tree.column(h, anchor=CENTER)

        with open('password.txt', 'rb') as f:
            file_load = pickle.load(f)

        data = dict(file_load)
        for login in file_load.keys():
            user_get = data.get(login)
            tree.insert('', END, values=tuple((login, user_get[1])))
            tree.bind('<Double-Button-1>', func=lambda event: self.command_block(tree, data))

        scroll_table = Scrollbar(self, command=tree.yview)
        tree.configure(yscrollcommand=scroll_table.set)
        scroll_table.pack(side=RIGHT, fill=Y)
        tree.pack(expand=YES, fill=BOTH)

    def command_block(self, tree, data):
        select = tree.selection()[0]
        values = tree.item(select, "values")

        if values[0] == 'admin':
            mb.showerror("Ошибка", "Блокировка администратора запрещена!")
            return

        if values[1] == 'True':
            data[values[0]][1] = False
            tree.set(select, column=1, value='False')
        else:
            data[values[0]][1] = True
            tree.set(select, column=1, value='True')
        with open('password.txt', 'wb') as file:
            pickle.dump(data, file)

class ChildLimitUser(Toplevel):
    def __init__(self):
        Toplevel.__init__(self)
        self.title("Ограничение юзеров")
        self.resizable(False, False)
        self.child()

    def child(self):
        tree = Treeview(self, show="headings", selectmode="browse")
        headings = ['Логин', 'Ограничение']
        tree["columns"] = headings
        tree["displaycolumns"] = headings
        for h in headings:
            tree.heading(h, text=h, anchor=CENTER)
            tree.column(h, anchor=CENTER)

        with open('password.txt', 'rb') as f:
            file_load = pickle.load(f)

        data = dict(file_load)
        for login in file_load.keys():
            user_get = data.get(login)
            tree.insert('', END, values=tuple((login, user_get[2])))
            tree.bind('<Double-Button-1>', func=lambda event: self.command_limit(tree, data))

        scroll_table = Scrollbar(self, command=tree.yview)
        tree.configure(yscrollcommand=scroll_table.set)
        scroll_table.pack(side=RIGHT, fill=Y)
        tree.pack(expand=YES, fill=BOTH)

    def command_limit(self, tree, data):
        select = tree.selection()[0]
        values = tree.item(select, "values")
        if values[1] == 'True':
            data[values[0]][2] = False
            tree.set(select, column=1, value='False')
        else:
            data[values[0]][2] = True
            tree.set(select, column=1, value='True')

        with open('password.txt', 'wb') as file:
            pickle.dump(data, file)

class WinAuthorization(WinGUI):
    def __init__(self):
        super(WinAuthorization, self).__init__()
        self.attempts = 0
        self.main()

    def main(self):
        root.geometry("355x290+{}+{}".format(int(root.winfo_screenwidth() / 2) - 210, int(root.winfo_screenheight() / 2) - 210))

        label = Label(root, text="Авторизация", font=("Times new Roman", 30))
        label.pack()

        label_login = Label(root, text="Логин:", font=("Times new Roman", 12))
        label_login.place(x=20, y=76)
        entry_login = Entry(root, width=43, textvariable=StringVar(), font=("Times new Roman", 11))
        entry_login.place(x=24, y=110)
        entry_login.focus()

        label_password = Label(root, text="Пароль:", font=("Times new Roman", 13))
        label_password.place(x=20, y=146)
        entry_password = Entry(root, width=43, textvariable=StringVar(), show="*", font=("Times new Roman", 11))
        entry_password.place(x=24, y=180)

        button = Button(root, text="Войти", font=("Times new Roman", 13), width=12, relief=GROOVE)
        button.config(command=lambda: self.command_entry([label, label_login, entry_login, entry_password, label_password, button], entry_login.get(), entry_password.get()))
        button.place(x=230, y=250)
        root.mainloop()

    def command_entry(self, items, login, password):
        if login == "":
            mb.showwarning("Внимание", "Введите, пожалуйста, логин!")
            return

        if path.isfile("password.txt") is False:
            md5_password = 'adminErvinAbkerimov'
            md5_password = md5(md5_password.encode()).hexdigest()
            data = {'admin': [md5_password, False, True, 5]}
            with open('password.txt', 'wb') as file:
                pickle.dump(data, file)

        with open('password.txt', 'rb') as f:
            file_load = pickle.load(f)

        data = dict(file_load)
        if data.get(login) is None:
            mb.showerror("Ошибка", "Пользователь с таким логином не найден!")
            return

        password += 'ErvinAbkerimov'
        password = md5(password.encode()).hexdigest()
        user_get = data.get(login)
        if password != user_get[0] and user_get[0]:
            self.attempts += 1
            if self.attempts == 3:
                mb.showerror("Ошибка", "Пароль введён не верно!\nПрограмма будет закрыта.")
                self.quit_app()
            elif (3 - self.attempts) == 1:
                mb.showerror("Ошибка", "Пароль введён не верно!\nУ вас ещё {} попытка.".format(3 - self.attempts))
            else:
                mb.showerror("Ошибка", "Пароль введён не верно!\nУ вас ещё {} попытки.".format(3 - self.attempts))
            return

        if user_get[1] is True:
            mb.showerror("Ошибка", "Ваш аккаунт заблокирован!")
            return

        for i in items:
            i.destroy()

        global user_info
        user_info = {'login': login, 'password': user_get[0], 'limit': user_get[2], 'length': user_get[3]}
        if is_valid_password(user_info['password'], user_info['length']):
            WinPanel()
        else:
            WinPassword(value=user_info['password'], length=user_info['length']).change()
            mb.showwarning("Внимание", "Вам нужно изменить пароль.\nДлина пароля не соблюдает правилам (Минимум {} симв.)".format(user_info['length']))

try:
    my_signature = str(GetComputerName()) + " | " + str(GetWindowsDirectory()) + " | " + str(GetSystemMetrics(0)) + " | " + str(GetSystemMetrics(1)) + " | " + str(GetSystemDirectory()) + " | " + str(getlogin())
    my_signature = sha512(my_signature.encode()).hexdigest()

    winkey = OpenKey(HKEY_CURRENT_USER, "Software\\Ervin Abkerimov", 0, KEY_ALL_ACCESS)
    win_signature = QueryValueEx(winkey, "MY SIGNATURE")[0]
    winkey.Close()
    if win_signature == my_signature:
        WinAuthorization()
    else:
        root.withdraw()
        mb.showerror("Ошибка", "Пожалуйста, переустановите программу!")
except:
    root.withdraw()
    mb.showerror("Ошибка", "Программа не установлена!")

