# Основной модуль приложения. Реализует создание интерфейса основного окна и обработку событий, вызванных
# взаимодействиями пользователя с элементами управления. Инициализирует процедуры генерации и обмена между клиентами
# файлами с открытыми и сессионными ключами, а также шифрацию, передачу и дешифрацию выбранных файлов с использованием
# сессионного ключа.
from datetime import datetime
import os
import shutil
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter.scrolledtext import ScrolledText
from tkinter.messagebox import showerror, showwarning, showinfo
import el_gamal as eg
import RC6 as rc6


# словарь для хранения всех объектов класса "клиент/абонент", с которыми взаимодействует наш клиент
# доступ к значению - по имени контрагента
agent_dict = {}


# класс "клиент/абонент"
# хранит все ключи клиентов/абонентов, с которыми взаимодействует наш клиент
class ExchangeKeys:
    def __init__(self, client_type, y, p, g, x, k, m):
        self.client_type = client_type
        self.y = y
        self.p = p
        self.g = g
        self.x = x
        self.k = k
        self.m = m


# делаем неактивными кнопки, дабы не реагировали во время расчётов
def set_disable():
    createClientWorkFolderBtn['state'] = 'disabled'
    assymKeysGenBtn['state'] = 'disabled'
    getOpKeyGenSessKeyBtn['state'] = 'disabled'
    getSessKeyBtn['state'] = 'disabled'
    selectEncFileNameBtn['state'] = 'disabled'
    encFileBtn['state'] = 'disabled'
    openDecFileBtn['state'] = 'disabled'
    decFileBtn['state'] = 'disabled'
    return


# возвращаем кнопкам активность
def set_enable():
    createClientWorkFolderBtn['state'] = 'normal'
    assymKeysGenBtn['state'] = 'normal'
    getOpKeyGenSessKeyBtn['state'] = 'normal'
    getSessKeyBtn['state'] = 'normal'
    selectEncFileNameBtn['state'] = 'normal'
    encFileBtn['state'] = 'normal'
    openDecFileBtn['state'] = 'normal'
    decFileBtn['state'] = 'normal'
    return


# создаём рабочую папку клиента; предварительно удаляем с таким же именем, если есть
def create_client_work_folder():
    if clientNameEntry.get() == '':
        showwarning(title="Внимание!", message="Не указано имя клиента!")
    else:
        client_folder_name = os.path.join(os.getcwd(), clientNameEntry.get())
        if os.path.exists(client_folder_name):
            shutil.rmtree(client_folder_name)
            log_update("Удалена папка " + client_folder_name)
        os.mkdir(client_folder_name)
        log_update("Создана папка " + client_folder_name)


# открываем диалог выбора файла для шифрования и вставляем имя файла в текстовое поле
def select_enc_file_name():
    filepath = filedialog.askopenfilename()
    encFilePathEnt.insert(0, filepath)
    log_update("Для шифрования выбран файл " + filepath)


# открываем диалог выбора файла для дешифрования и вставляем имя файла в текстовое поле
def select_dec_file_name():
    filepath = filedialog.askopenfilename()
    decFilePathEnt.insert(0, filepath)
    log_update("Для дешифрации выбран файл " + filepath)


# меняем имя клиента в заголовке главного окна
def client_name_change(event):
    mainWindow.title("Имя клиента: " + clientNameEntry.get())


# генерируем ключи асиметричного шифрования клиента
# передаём открытые компоненты абоненту
def assym_keys_gen():
    set_disable()
    client_name = clientNameEntry.get()
    abonent_name = abonentNameEntry.get()
    client_folder_name = os.path.join(os.getcwd(), clientNameEntry.get())
    abonent_folder_name = os.path.join(os.getcwd(), abonentNameEntry.get())
    if not os.path.exists(client_folder_name) or clientNameEntry.get() == '':
        showwarning(title="Внимание!", message="Не указано имя клиента!")
    elif not os.path.exists(abonent_folder_name) or abonentNameEntry.get() == '':
        showwarning(title="Внимание!", message="Не найдена папка абонента!")
    else:
        egKeySize = int(elGamalKeySizeCombobox.get())  # длина ассим. ключа в битах
        primTest = primTestMethodCombobox.get()  # метод проверки ключа на простоту
        primTestRounds = int(primTestRoundsCnt.get())  # кол-во раундов проверки на простоту
        clientKeys = eg.get_keys_alice(egKeySize, primTest, primTestRounds)  # генерируем ассим. ключи
        agent_dict[abonent_name] = ExchangeKeys(
            "abonent",
            clientKeys.y,
            clientKeys.p,
            clientKeys.g,
            clientKeys.x,
            None,
            None
        )
        f = open(os.path.join(abonent_folder_name, client_name + ".PK"), "w")
        f.write("{}\n{}\n{}".format(
            agent_dict[abonent_name].y,
            agent_dict[abonent_name].p,
            agent_dict[abonent_name].g
        ))
        f.close()
        log_update("Абоненту {} переданы открытые ключи: y = {}, p = {}, g = {}. Сгенерирован закрытый ключ дешифрации x = {}"
            .format(
            abonent_name,
            agent_dict[abonent_name].y,
            agent_dict[abonent_name].p,
            agent_dict[abonent_name].g,
            agent_dict[abonent_name].x
            )
        )
    set_enable()

# забираем открытые компоненты ключей асиметричного шифрования, сгенерированные клиентом
# генерируем ключ асиметричного шифрования абонента
# генерируем сессионный ключ
# шифруем сессионный ключ на ключе асиметричного шифрования абонента
def get_op_key_gen_sess_key():
    set_disable()
    # помним: если мы получаем открытый ключ, то абонент (Bob) - это мы
    abonent_name = clientNameEntry.get()
    abonent_folder_name = os.path.join(os.getcwd(), abonent_name)
    # если наша папка ещё не создана, то искать мы в ней не можем
    if not os.path.exists(abonent_folder_name) or abonentNameEntry.get() == '':
        showwarning(title="Внимание!", message="Не создана папка клиента!")
    else:
        key_file_list = os.listdir(abonent_folder_name)  # получили список всех файлов в нашей папке
        # прошли в цикле по своей папке, извлекли названия всех файлов, которые имеют вид <имя_клиента>.PK
        cnt = 0  # счётчик найденных и обработанных файлов
        for key_file_name in key_file_list:
            client_name, extension = key_file_name.split(".")[0], key_file_name.split(".")[1]
            if extension == "PK":
                cnt = cnt + 1
                log_update("Найден файл открытых ключей " + key_file_name)
                # для каждого такого файла проверяем, есть ли папка <имя_клиента> (нам туда ж ещё ключи a и b записывать..)
                client_folder_name = os.path.join(os.getcwd(), client_name)
                if not os.path.exists(client_folder_name):
                    log_update("Внимание! Не найдена папка клиента {}!".format(client_name))
                else:
                    # открываем найденный файл с открытыми ключами Alice, читаем y, p, g
                    f = open(os.path.join(abonent_folder_name, key_file_name), "r")
                    y = int(f.readline())
                    p = int(f.readline())
                    g = int(f.readline())
                    f.close()
                    log_update("От клиента {} получены открытые ключи: y = {}, p = {}, g = {}".format(client_name, y, p, g))

                    # генерим ключи k и m, шифруем m на k, создаём открытые компоненты шифротекста a и b
                    # длина сессионного ключа m в символах
                    rc6KeySize = int(rc6KeySizeCombobox.get())  # длина сессионного ключа в байтах/символах
                    primTest = primTestMethodCombobox.get()  # метод проверки ключа на простоту
                    primTestRounds = int(primTestRoundsCnt.get())  # кол-во раундов проверки на простоту
                    abonentKeys = eg.el_gamal_encrypt(eg.AliceKeys(y, p, g, None), rc6KeySize, primTest, primTestRounds)
                    m = abonentKeys[0]
                    k = abonentKeys[1].k
                    a = abonentKeys[1].a
                    b = abonentKeys[1].b
                    log_update("Сгенерированы секретный ключ шифрования k = {}, секретный сессионный ключ m = {}, открытые компоненты шифротекста a, b = {}, {}".format(k, m, a, b))

                    # делаем запись в словарь агентов по ключу <имя_клиента> ["client", y, p, g, None, k, m]
                    agent_dict[client_name] = ExchangeKeys("client", y, p, g, None, k, m)

                    # записываем сгенерированные ключи a и b в файл /<имя_клиента>/<имя_абонента>.SK.enc
                    f = open(os.path.join(client_folder_name, abonent_name + ".SK"), "w")
                    f.write("{}\n".format(a))
                    for bi in b:
                        f.write("{}\n".format(bi))
                    f.close()
                    log_update("Клиенту {} переданы открытые компоненты шифротекста a, b = {}, {}".format(client_name, a, b))

                    # удаляем файл <имя_клиента>.PK
                    os.remove(os.path.join(abonent_folder_name, key_file_name))
        if cnt == 0:
            showinfo(title="Информация", message="Файлы с открытыми ключами не обнаружены")
    set_enable()


# забираем сессионный ключ, зашифрованный на ключе асиметричного шифрования абонента
# дешифруем на ключе ассимеричной дешифрации клиента
def get_sess_key():
    set_disable()
    # если мы забираем открытые ключи (компоненты шифротекста) a и b, то, значит, мы Alice, т.е. клиент
    client_name = clientNameEntry.get()
    client_folder_name = os.path.join(os.getcwd(), client_name)
    if not os.path.exists(client_folder_name) or clientNameEntry.get() == '':  # если наша папка ещё не создана, то искать мы в ней не можем
        showwarning(title="Внимание!", message="Не создана папка клиента!")
    else:
        key_file_list = os.listdir(client_folder_name)  # получили список всех файлов в нашей папке
        # прошли в цикле по своей папке, извлекли названия всех файлов, которые имеют вид <имя_клиента>.SK
        cnt = 0  # счётчик найденных и обработанных файлов
        for key_file_name in key_file_list:
            abonent_name, extension = key_file_name.split(".")[0], key_file_name.split(".")[1]
            if extension == "SK":
                cnt = cnt + 1
                log_update("Найден файл с сессионным ключом " + key_file_name)

                # открываем файл с сессионным ключом, читаем компоненты шифротекста a и b
                f = open(os.path.join(client_folder_name, key_file_name), "r")
                keys = f.readlines()  # прочитали сразу все строки в один список
                a = int(keys[0])  # 0-я строка - это компонента a
                # остальные строки (элементы списка), начиная со 1-го, проходим итератором,
                # преобразуем в integer и делаем из них новый список (компоненту b)
                b = [int(item) for item in keys[1:]]
                f.close()
                log_update("От абонента {} получены открытые компоненты шифротекста a, b = {}, {}".format(abonent_name, a, b))

                # расшифровываем сессионный ключ
                decoded_m = eg.el_gamal_decrypt(a, b, agent_dict[abonent_name].x, agent_dict[abonent_name].p)

                # делаем запись в словарь агентов по ключу <имя_клиента>: [..., ..., ..., ..., ..., ..., m]
                # т.е. такая запись уже есть, добавляем в неё значение полученного и расшифрованного сессионного ключа
                agent_dict[abonent_name].m = decoded_m
                log_update("От абонента {} получен сессионный ключ m = {}".format(abonent_name, decoded_m))

                # удаляем файл <имя_клиента>.SK
                os.remove(os.path.join(client_folder_name, key_file_name))
        if cnt == 0:
            showinfo(title="Информация", message="Файлы с сессионными ключами не обнаружены")
    set_enable()


def encrypt_file():
    set_disable()
    # проверяем наличие всех ключей клиента и абонента
    if clientNameEntry.get() == '':
        showwarning(title="Ошибка!", message="Не определёно имя клиента!")
        return
    if abonentNameEntry.get() == '':
        showwarning(title="Ошибка!", message="Не определёно имя абонента!")
        return
    if abonentNameEntry.get() not in agent_dict:
        showwarning(title="Ошибка!", message="Не произведён обмен ключами!")
        return
    if agent_dict[abonentNameEntry.get()].m == '' or agent_dict[abonentNameEntry.get()].m is None:
        showwarning(title="Ошибка!", message="От абонента не получен сессионный ключ!")
        return
    file_enc_in = encFilePathEnt.get()
    if not os.path.exists(file_enc_in):
        showwarning(title="Ошибка!", message="Не найден файл для шифрования!")
        return
    abonent_name = abonentNameEntry.get()
    file_enc_out = os.path.join(os.getcwd(), abonent_name, (os.path.basename(file_enc_in) + ".enc"))
    key = agent_dict[abonentNameEntry.get()].m
    mode = rc6EncryptModeCombobox.get()
    w = rc6BlockSizeCombobox.get()
    r = rc6RoundNumberCombobox.get()
    encrypting = rc6.rc6(file_in=file_enc_in, file_out=file_enc_out, key=key, mode=mode, block=int(w), rounds=int(r), window=mainWindow, pbar=encProgress)
    log_update("Начато шифрование файла {}".format(file_enc_in))
    enc_result = encrypting.transform("encrypt")
    log_update(enc_result)
    log_update("Записан зашифрованный файл {}".format(file_enc_out))
    set_enable()


def decrypt_file():
    set_disable()
    # проверяем наличие всех ключей клиента и абонента
    if clientNameEntry.get() == '':
        showwarning(title="Ошибка!", message="Не определёно имя клиента!")
        return
    if abonentNameEntry.get() == '':
        showwarning(title="Ошибка!", message="Не определёно имя абонента!")
        return
    if abonentNameEntry.get() not in agent_dict:
        showwarning(title="Ошибка!", message="Не произведён обмен ключами!")
        return
    if agent_dict[abonentNameEntry.get()].m == '' or agent_dict[abonentNameEntry.get()].m is None:
        showwarning(title="Ошибка!", message="От абонента не получен сессионный ключ!")
        return
    file_dec_in = decFilePathEnt.get()
    if not os.path.exists(file_dec_in):
        showwarning(title="Ошибка!", message="Не найден файл для дешифрации!")
        return
    client_name = clientNameEntry.get()
    file_dec_out = os.path.join(os.getcwd(), client_name, (os.path.basename(file_dec_in) + ".dec"))
    key = agent_dict[abonentNameEntry.get()].m
    mode = rc6EncryptModeCombobox.get()
    w = rc6BlockSizeCombobox.get()
    r = rc6RoundNumberCombobox.get()
    encrypting = rc6.rc6(file_in=file_dec_in, file_out=file_dec_out, key=key, mode=mode, block=int(w), rounds=int(r), window=mainWindow, pbar=decProgress)
    log_update("Начата дешифрация файла {}".format(file_dec_in))
    dec_result = encrypting.transform("decrypt")
    log_update(dec_result)
    log_update("Записан дешифрованный файл {}".format(file_dec_out))
    set_enable()
    

# записываем в лог изменение имени клиента
def client_name_changed(event):
    if clientNameEntry.get() == abonentNameEntry.get():
        showerror(title="Ошибка!", message="У клиента и абонента должны быть разные имена!")
        clientNameEntry.delete(0, tk.END)
    else:
        if clientNameEntry.get() != "":
            log_update("Имя клиента изменено на " + clientNameEntry.get())


# записываем в лог изменение имени абонента
def abonent_name_changed(event):
    if abonentNameEntry.get() == clientNameEntry.get():
        showerror(title="Ошибка!", message="У абонента и клиента должны быть разные имена!")
        abonentNameEntry.delete(0, tk.END)
    else:
        if abonentNameEntry.get() != "":
            log_update("Имя абонента изменено на " + abonentNameEntry.get())


# записываем в лог изменение режима шифрования
def rc6_encrypt_mode_changed(event):
    log_update("Выбран режим шифрования " + rc6EncryptModeCombobox.get())


# записываем в лог изменение метода проверки открытого ключа на целое
def prim_test_method_changed(event):
    log_update("Выбран метод проверки на целое " + primTestMethodCombobox.get())


# записываем в лог изменение количества раундов проверки на целое
def prim_test_cnt_changed(event):
    log_update("Установлено число раундов проверки на целое число при генерации открытых ключей " + primTestRoundsCnt.get())


# записываем в лог выбор длины ключа ассиметричного алгоритма
def elgamal_key_size_changed(event):
    log_update("Выбран размер ключа ассиметричного алгоритма " + elGamalKeySizeCombobox.get())


# записываем в лог изменение длины ключа симметричного алгоритма
def rc6_key_size_changed(event):
    log_update("Выбран размер закрытого сессионного ключа симметричного алгоритма " + rc6KeySizeCombobox.get())


# записываем в лог изменение размера блока шифрования симметричного алгоритма
def rc6_block_size_changed(event):
    log_update("Выбран размер блока шифрования симметричного алгоритма " + rc6BlockSizeCombobox.get())


# записываем в лог изменение количества раундов шифрования симметричного алгоритма
def rc6_round_number_changed(event):
    log_update("Выбрано количество раундов шифрования симметричного алгоритма " + rc6RoundNumberCombobox.get())


# добавляем строку в окно лога
def log_update(message_string):
    current_time = datetime.now().strftime("%d.%m.%y %H:%M:%S ")
    logText.configure(state=tk.NORMAL)
    logText.insert("1.0", current_time + message_string + "\n")
    logText.configure(state=tk.DISABLED)


# главное окно
mainWindow = tk.Tk()
mainWindow.title("Имя клиента:")
mainWindow.geometry("1014x600")
mainWindow.resizable(False, False)

# поле ввода с именем клиента + кнопка создания рабочей папки клиента
tk.Label(text="Имя клиента ").grid(row=1, column=1, sticky=tk.E)
#
clientNameEntry = tk.Entry(width=90)
clientNameEntry.bind("<KeyRelease>", client_name_change)
clientNameEntry.bind("<FocusOut>", client_name_changed)
clientNameEntry.grid(row=1, column=2)
#
createClientWorkFolderBtn = ttk.Button(text="Создать папку клиента", width=28, command=create_client_work_folder)
createClientWorkFolderBtn.grid(row=1, column=3, columnspan=1, sticky=tk.W)

# поле ввода с именем абонента
tk.Label(text="Имя абонента ").grid(row=2, column=1, sticky=tk.E)
#
abonentNameEntry = tk.Entry(width=90)
abonentNameEntry.bind("<FocusOut>", abonent_name_changed)
abonentNameEntry.grid(row=2, column=2)

# элементы для генерации и обмена ключами
tk.Label(text="Генерация ключей ").grid(row=4, column=1, sticky=tk.E)
#
tk.Label(text="Метод проверки на целое ").grid(row=3, column=3, sticky=tk.E)
primTestMethod = ["FERMAT", "MILLER-RABIN", "SOLOVAY-STRASSEN"]
primTestMethodCombobox = ttk.Combobox(values=primTestMethod, width=20)
primTestMethodCombobox.insert(0, "FERMAT")  # значение при создании
primTestMethodCombobox.bind("<<ComboboxSelected>>", prim_test_method_changed)
primTestMethodCombobox.grid(row=3, column=4)
#
tk.Label(text="Раундов проверки на целое ").grid(row=4, column=3, sticky=tk.E)
primTestRoundsCnt = ttk.Spinbox(from_=1, to=100, increment=1, width=20)
primTestRoundsCnt.insert(0, "64")  # значение при создании
primTestRoundsCnt.bind("<FocusOut>", prim_test_cnt_changed)
primTestRoundsCnt.grid(row=4, column=4, sticky=tk.W)
#
tk.Label(text="Длина ассим. ключа ").grid(row=5, column=3, sticky=tk.E)
elGamalKeySize = ["16", "32", "64", "128"]
elGamalKeySizeCombobox = ttk.Combobox(values=elGamalKeySize, width=20)
elGamalKeySizeCombobox.insert(0, "64")  # значение при создании
elGamalKeySizeCombobox.bind("<<ComboboxSelected>>", elgamal_key_size_changed)
elGamalKeySizeCombobox.grid(row=5, column=4)
#
tk.Label(text="Длина сессионного ключа ").grid(row=6, column=3, sticky=tk.E)
rc6KeySize = ["8", "16", "32", "64", "128", "256"]
rc6KeySizeCombobox = ttk.Combobox(values=rc6KeySize, width=20)
rc6KeySizeCombobox.insert(0, "64")  # значение при создании
rc6KeySizeCombobox.bind("<<ComboboxSelected>>", rc6_key_size_changed)
rc6KeySizeCombobox.grid(row=6, column=4)
#
tk.Label(text="Длина блока шифрования ").grid(row=7, column=3, sticky=tk.E)
rc6BlockSize = ["16", "32", "64", "128"]
rc6BlockSizeCombobox = ttk.Combobox(values=rc6BlockSize, width=20)
rc6BlockSizeCombobox.insert(0, "64")  # значение при создании
rc6BlockSizeCombobox.bind("<<ComboboxSelected>>", rc6_block_size_changed)
rc6BlockSizeCombobox.grid(row=7, column=4)
#
tk.Label(text="Число раундов шифрования ").grid(row=8, column=3, sticky=tk.E)
rc6RoundNumber = ["10", "20", "30"]
rc6RoundNumberCombobox = ttk.Combobox(values=rc6RoundNumber, width=20)
rc6RoundNumberCombobox.insert(0, "20")  # значение при создании
rc6RoundNumberCombobox.bind("<<ComboboxSelected>>", rc6_round_number_changed)
rc6RoundNumberCombobox.grid(row=8, column=4)
#
assymKeysGenBtn = ttk.Button(text="[клиент] Сгенерировать публичный ключ (инициатора)", width=89, command=assym_keys_gen)
assymKeysGenBtn.grid(row=3, column=2, sticky=tk.W)
#
getOpKeyGenSessKeyBtn = ttk.Button(text="[абонент] Получить пуб. ключ -> Генерировать сесс. ключ -> Передать сесс. ключ инициатору", width=89,
                                   command=get_op_key_gen_sess_key)
getOpKeyGenSessKeyBtn.grid(row=4, column=2, sticky=tk.W)
#
getSessKeyBtn = ttk.Button(text="[клиент] Получить сессионный ключ от абонента", width=89, command=get_sess_key)
getSessKeyBtn.grid(row=5, column=2, sticky=tk.W)

# выпадающий список с режимами шифрования RC6
tk.Label(text="Режим шифрования RC6 ").grid(row=6, column=1, sticky=tk.E)
rc6EncryptMode = ["ECB", "CBC", "CFB", "OFB"]
rc6EncryptModeCombobox = ttk.Combobox(values=rc6EncryptMode, width=87)
rc6EncryptModeCombobox.insert(0, "ECB")  # значение при создании
rc6EncryptModeCombobox.bind("<<ComboboxSelected>>", rc6_encrypt_mode_changed)
rc6EncryptModeCombobox.grid(row=6, column=2, sticky=tk.W)

# диалог выбора файла для шифрования
tk.Label(text="Файл для шифрования ").grid(row=10, column=1, sticky=tk.E)
#
encFilePathEnt = tk.Entry(width=90)
encFilePathEnt.grid(row=10, column=2, sticky=tk.W)
#
selectEncFileNameBtn = ttk.Button(text="...", command=select_enc_file_name, )
selectEncFileNameBtn.grid(row=10, column=3, sticky=tk.W)
#
encFileBtn = ttk.Button(text="Зашифровать", width=15, command=encrypt_file)
encFileBtn.grid(row=10, column=3, columnspan=1, sticky=tk.E)

# прогресс-бар шифрования
encProgress = ttk.Progressbar(orient="horizontal", length=1011, value=0)
encProgress.grid(row=11, column=1, columnspan=4)

# диалог выбора файла для дешифрования
tk.Label(text="Файл для дешифрации ").grid(row=12, column=1, sticky=tk.E)
#
decFilePathEnt = tk.Entry(width=90)
decFilePathEnt.grid(row=12, column=2, sticky=tk.W)
#
openDecFileBtn = ttk.Button(text="...", command=select_dec_file_name)
openDecFileBtn.grid(row=12, column=3, sticky=tk.W)
#
decFileBtn = ttk.Button(text="Дешифровать", width=15, command=decrypt_file)
decFileBtn.grid(row=12, column=3, columnspan=1, sticky=tk.E)

# прогресс-бар дешифрования
decProgress = ttk.Progressbar(orient="horizontal", length=1011, value=0)
decProgress.grid(row=13, column=1, columnspan=4)

# окно протокола
logText = ScrolledText(height=21, width=141, state=tk.DISABLED, font=("Courier New", 9))
logText.grid(row=14, column=1, columnspan=4)

log_update("Начало работы клиента")
log_update("Выбран режим шифрования ECB")
log_update("Выбран размер ключа ассиметричного алгоритма 64")
log_update("Выбран размер закрытого сессионного ключа симметричного алгоритма 64")
log_update("Выбран размер блока шифрования симметричного алгоритма 64")
log_update("Выбрано количество раундов шифрования симметричного алгоритма 20")
log_update("Выбран метод проверки на целое FERMAT")
log_update("Установлено число раундов проверки на целое число при генерации открытых ключей 64")

mainWindow.mainloop()
