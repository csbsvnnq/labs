from tkinter import *
from tkinter import messagebox as mb, filedialog as fd
from tkinter.ttk import Progressbar
from time import sleep
from os import path, getlogin
from hashlib import sha512
from win32api import GetComputerName, GetWindowsDirectory, GetSystemMetrics, GetSystemDirectory
from winreg import *
#from git import Repo

root = Tk()

class WinGUI:
    def __init__(self):
        root.title("Лабораторная работа (1-3)")
        root.resizable(False, False)
        root.geometry("530x350+{0}+{1}".format(int(root.winfo_screenwidth() / 2) - 210, int(root.winfo_screenheight() / 2) - 210))
        root.protocol("WM_DELETE_WINDOW", lambda: self.quit_app())

        self.label = Label(root, text="", font=("Times new Roman", 30))
        self.label.pack()

        self.menu = Menu(root)
        root.config(menu=self.menu)
        info = Menu(self.menu, tearoff=0)
        info.add_command(label="О програме", command=self.information)
        self.menu.add_cascade(label="Справка", menu=info)

        self.button_next = Button(root, text="Далее", font=("Times new Roman", 13), width=9, relief=GROOVE)
        #        button_back.config(command=lambda: self.command_entry([label, label_login, entry_login, entry_password, label_password, button], entry_login.get(), entry_password.get()))
        self.button_next.place(x=430, y=300)

        self.button_back = Button(root, text="Назад", font=("Times new Roman", 13), width=9, relief=GROOVE)
        self.button_back.place(x=330, y=300)

        self.button_exit = Button(root, text="Отмена", font=("Times new Roman", 13), width=9, relief=GROOVE, command=self.quit_app)
        self.button_exit.place(x=15, y=300)

    def information(self):
        mb.showinfo("Информация", "Автор: Абкеримов Эрвин\nГруппа: ФБ-73\nВариант: 1")

    def quit_app(self, flag=False):
        if flag is True:
            answer = mb.askyesno(title="Вопрос", message="Вы уверенны, что хотите прервать установку программы?")
            if answer is True:
                root.destroy()
                exit()
        else:
            root.destroy()
            exit()

class WinInstaller(WinGUI):
    def __init__(self):
        super(WinInstaller, self).__init__()
        self.hello(None)

    def hello(self, items):
        if items is not None:
            for i in items:
                i.destroy()

        self.label['text'] = "Добро пожаловать"
        label_info1 = Label(root, text="Вас приветсует установщик программы Лабораторной №1.", font=("Times new Roman", 14))
        label_info2 = Label(root, text="Нажмите \"Далее\", чтобы продолжить, или \"Отмена\", чтобы", font=("Times new Roman", 14))
        label_info3 = Label(root, text="выйти из установщика.", font=("Times new Roman", 14))
        label_info1.place(x=15, y=70)
        label_info2.place(x=15, y=100)
        label_info3.place(x=15, y=130)

        self.button_back.config(state=DISABLED)
        self.button_next.config(command=lambda: self.choose_path([label_info1, label_info2, label_info3]))

        root.mainloop()

    def choose_path(self, items):
        for i in items:
            i.destroy()

        self.label['text'] = "Установка"

        label_info = Label(root, text="Выберите путь для установки программы:", font=("Times new Roman", 13))
        label_info.place(x=15, y=70)

        entry_path = Entry(root, width=48, textvariable=StringVar(), relief=GROOVE, font=("Times new Roman", 12))
        entry_path.insert(0, "C:/Program Files")
        entry_path.place(x=20, y=100)

        button_path = Button(root, text="Обзор...", font=("Times new Roman", 11), width=9, relief=GROOVE, command=lambda: self.command_choose_path(entry_path))
        button_path.place(x=424, y=97)

        items = [label_info, entry_path, button_path]
        self.button_next.config(text="Далее", command=lambda: self.install(items, entry_path.get()))
        self.button_back.config(state=NORMAL, command=lambda: self.hello(items))

    def command_choose_path(self, entry_path):
        choose_path = fd.askdirectory()
        if choose_path:
            entry_path.delete(0, END)
            entry_path.insert(0, choose_path)

    def install(self, items, entry_path):
        if entry_path == "":
            mb.showwarning("Внимание", "Вы не указали путь для установки программы.")
            return

        if path.exists(entry_path) is False:
            mb.showerror("Ошибка", "Указаного пути не существует, выберите другой путь!")
            return

        status = False
        try:
            my_signature = str(GetComputerName()) + " | " + str(GetWindowsDirectory()) + " | " + str(GetSystemMetrics(0)) + " | " + str(GetSystemMetrics(1)) + " | " + str(GetSystemDirectory()) + " | " + str(getlogin())
            my_signature = sha512(my_signature.encode()).hexdigest()

            try:
                winkey = CreateKey(HKEY_CURRENT_USER, "Software\\Ervin Abkerimov")
            except:
                winkey = OpenKey(HKEY_CURRENT_USER, "Software\\Ervin Abkerimov", 0, KEY_ALL_ACCESS)

            SetValueEx(winkey, "MY SIGNATURE", 0, REG_SZ, my_signature)
            winkey.Close()

            #Repo.clone_from(url='http://user:password@github.com/user/any.git', to_path=entry_path)
        except:
            pass
        else:
            status = True

        for i in items:
            i.destroy()

        label_info = Label(root, text="Программа будет установлена в: {}".format(entry_path), font=("Times new Roman", 12))
        label_info.place(x=15, y=70)
        progressbar = Progressbar(root, orient="horizontal", length=500, mode="determinate")
        progressbar.place(x=15, y=100)

        items = [label_info, progressbar]
        self.button_back.config(command=lambda: self.choose_path(items))
        self.button_next.config(text="Установить", command=lambda: self.process_install(status, items))

    def process_install(self, status, items):
        self.button_exit.config(state=DISABLED)
        self.button_next.config(state=DISABLED)
        self.button_back.config(state=DISABLED)

        items[1].start()
        for i in range(100):
            sleep(.1)
            items[1].step(1)
            items[1].update_idletasks()

        items[1].stop()
        if status is False:
            mb.showerror("Ошибка", "Не известная ошибка установки!\nУстановка будет прекращена.")
            self.quit_app(False)

        for i in items:
            i.destroy()

        self.install_success()

    def install_success(self):
        self.label['text'] = "Успех"
        label_info1 = Label(root, text="Программа успешно установлена!", font=("Times new Roman", 14))
        label_info2 = Label(root, text="Нажмите \"Завершить\", для завершения установки", font=("Times new Roman", 14))
        label_info1.place(x=15, y=70)
        label_info2.place(x=15, y=100)

        self.button_exit.destroy()
        self.button_back.destroy()
        self.button_next.config(state=NORMAL, text="Завершить", command=lambda: self.quit_app(False))

WinInstaller()
