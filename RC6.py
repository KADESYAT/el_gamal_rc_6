from pathlib import Path
from datetime import datetime
import random
from encrypt_mode_enumerator import encrypt_mode
from bit_rotation import bit_rotation_left, bit_rotation_right
from tkinter import *
from tkinter import ttk


# Класс, описывающий процедуру блочного симметричного шифрования по алгоритму RC6
# описание в файле "theory/Rivest R.L., Robshaw M.J.B., Sidney R., Yin Y.L. - The RC6 Block Cipher.pdf"
# (оригинальный авторский файл от 1998 года, рили :)
class rc6:
    def __init__(self, file_in, file_out, key, mode, block: int, rounds: int, window: Tk, pbar: ttk):
        self.file_in = file_in
        self.file_out = file_out
        self.window = window  # объект оглавного окна
        self.pbar = pbar  # объект ProgressBar для отображения прогресса шифрации/дешифрации
        self.key = key  # секретный ключ
        # установка режима шифрования
        if mode == "ECB":
            self.mode = encrypt_mode.ECB
        elif mode == "CBC":
            self.mode = encrypt_mode.CBC
        elif mode == "OFB":
            self.mode = encrypt_mode.OFB
        else:
            self.mode = encrypt_mode.CFB

        self.__w = block  # Размер слова в битах
        self.__r = rounds  # количество раундов шифрования
        self.__source_filename = file_in  # имя исходного файла
        self.__destination_filename = file_out  # имя преобразованного файла

        # "Магические" константы для генерации раундовых ключей при различных длинах слова w в битах:
        self.__Pw: dict[int, int] = {16: 0xb7e1, 32: 0xb7e15163, 64: 0xb7e151628aed2a6b}
        self.__Qw: dict[int, int] = {16: 0x9e37, 32: 0x9e3779b9, 64: 0x9e3779b97f4a7c15}

        # генерируем массив раундовых ключей
        self.__S = self.__generate_round_keys(self.__r, self.key, self.__w, self.__Pw[self.__w], self.__Qw[self.__w])

        # генерируем вектор инициализации
        self.__vi = self.__get_init_vector(mode, self.__w)

    # Вызываемый пользователем метод шифрования/дешифрации входного файла в выходной файл
    def transform(self, act: str) -> str:
        if act == 'encrypt':
            try:
                result = self.__encrypt(self.file_in, self.file_out, self.__S, self.__vi, self.__w, self.__r, self.mode, self.window, self.pbar)
            except:
                result = "Внимание, в процессе шифрования произошла ошибка!"
        elif act == 'decrypt':
            try:
                result = self.__decrypt(self.file_in, self.file_out, self.__S, self.__w, self.__r, self.mode, self.window, self.pbar)
            except:
                result = "Внимание, в процессе дешифрации произошла ошибка! Проверьте целостность исходного файла и соответствие режимов шифрования и дешифрации!"
        else:
            result = None
        return result

    # функция f для перемешивания ключа
    def __f(self, x, p):
        return (x * ((2 * x + 1) % p)) % p

    # процедура генерации массива раундовых ключей
    def __generate_round_keys(self, r: int, key: str, w: int, Pw: int, Qw: int) -> list:
        # Дополнение ключа нулями слева до кратности w
        key_bit = bin(int.from_bytes(bytes(key, "utf-8"), "big"))[2:]  # ключ - строка символов -> ключ - строка из знаков битов ("1" и "0")
        while len(key_bit) % w != 0:
            key_bit = "0" + key_bit

        # Конвертация секретного ключа из массива битов key в массив L
        keyLen = len(key_bit) // 8  # Размер ключа в байтах
        c = (8 * keyLen) // w  # число w-битных слов в ключе
        L = []
        for i in range(
                c):  # Преобразование (разбиение) ключа в массив L из c слов, из текстового двоичного вида в целое
            L.append(int(key_bit[(i * w):((i * w) + w)], 2))

        # Заполнение расширенного массива ключей
        S = [Pw, ]
        for i in range(2 * r + 3):
            S.append(S[i] + Qw)

        i, j, a, b = 0, 0, 0, 0

        # Формирование массива раундовых ключей (перемешиваем массивы)
        v = 3 * max(c, 2 * r + 4)
        for counter in range(v):
            S[i] = bit_rotation_left((S[i] + a + b), w, 3)
            a = S[i]
            L[j] = bit_rotation_left((L[j] + a + b), w, (a + b) % w)
            b = L[j]
            i = (i + 1) % (2 * r + 4)
            j = (j + 1) % c
        return S

    # процедура генерации вектора инициализации длиной до 4*w бит для режимов CBC, OFB и CFB
    def __get_init_vector(self, mode: encrypt_mode, w: int) -> int:
        vi = 0
        if mode != encrypt_mode.ECB:
            vi = random.randint(1, pow(2, 4 * w - 1))
        return vi

    # процедура шифрования входного файла
    def __encrypt(self, file_in, file_out, S, vi, w, r, mode: encrypt_mode, window, pbar):
        wb = w // 8  # размер слова в байтах
        wb2 = wb * 2
        wb3 = wb * 3
        wb4 = wb * 4
        wl = w.bit_length() - 1  # log2(w)
        p = 1 << w  # значение модуля 2**w для расчётов в раунде шифрования

        fSize = Path(file_in).stat().st_size  # Получаем размер файла для шифрования в байтах
        fReadCycles = int((fSize // wb4) + (1 % (fSize % wb4 + 1)))  # рассчитываем число циклов чтения блоков длиной 4*wb для шифрования
        paddCount = fReadCycles * wb4 - fSize  # рассчитываем количество байт набивки до кратности последнего блока 4*wb байта

        inputFile = open(file_in, "rb")
        outputFile = open(file_out, "wb")

        encStartTime = datetime.now()  # время начала шифрования

        if mode != encrypt_mode.ECB:
            outputFile.write(vi.to_bytes(wb4, "big"))  # записываем vi в начало шифруемого файла
            syncroMessage = vi  # начальное значение синхропосылки = вектор инициализации

        # инициализация прогресс-бара
        if window is not None and pbar is not None:
            self.pbar['maximum'] = fReadCycles
            self.pbar['value'] = 0
            self.window.update()

        for i in range(fReadCycles):  # Цикл по блокам в 4 слова
            # обновление значения прогресс-бара
            if window is not None and pbar is not None:
                if i % (fReadCycles // 10) == 0:
                    self.pbar['value'] += (fReadCycles // 10)
                    self.window.update()

            buffer_read = bytearray(inputFile.read(wb4))  # читаем из файла целый блок в буфер
            if i == (fReadCycles - 1):  # если блок последний, то дополняем его в конце до кратности 4*w набивкой типа PKCS7
                for pad_i in range(paddCount):
                    buffer_read.append(paddCount)

            if mode == encrypt_mode.ECB:
                buffer = buffer_read
            elif mode == encrypt_mode.CBC:
                buffer = bytearray((int.from_bytes(bytes(buffer_read), "big") ^ syncroMessage).to_bytes(wb4, "big"))
            elif mode == encrypt_mode.CFB or mode == encrypt_mode.OFB:
                buffer = bytearray(syncroMessage.to_bytes(wb4, "big"))

            # разбиваем буфер на регистры длиной в 1 слово
            A = int.from_bytes(bytes(buffer[0:wb]), "big")
            B = int.from_bytes(bytes(buffer[wb:wb2]), "big")
            C = int.from_bytes(bytes(buffer[wb2:wb3]), "big")
            D = int.from_bytes(bytes(buffer[wb3:wb4]), "big")

            # пропускаем регистры через сеть Фейстеля
            A, B, C, D = self.__feistel_net_enc(A, B, C, D, w, wl, p, S, r)

            # для записи в файл разбиваем каждый зашифрованный регистр на wb байт
            A = A.to_bytes(wb, "big")
            B = B.to_bytes(wb, "big")
            C = C.to_bytes(wb, "big")
            D = D.to_bytes(wb, "big")
            out = int.from_bytes(A + B + C + D, "big")

            if mode == encrypt_mode.CBC:
                syncroMessage = out
            elif mode == encrypt_mode.CFB or mode == encrypt_mode.OFB:
                buffer_write = bytearray((int.from_bytes(bytes(buffer_read), "big") ^ out).to_bytes(wb4, "big"))
                if mode == encrypt_mode.CFB:
                    syncroMessage = int.from_bytes(bytes(buffer_write), "big")
                else:
                    syncroMessage = out
                # для записи в файл разбиваем каждый преобразованный зашифрованный регистр на wb байт
                A = bytes(buffer_write[0:wb])
                B = bytes(buffer_write[wb:wb2])
                C = bytes(buffer_write[wb2:wb3])
                D = bytes(buffer_write[wb3:wb4])

            # записываем зашифрованные регистры в выходной файл
            outputFile.write(A + B + C + D)

        outputFile.close()
        encEndTime = datetime.now()

        result = "Начало шифрования: {}\nКонец шифрования: {}\nПродолжительность шифрования: {}\nСкорость шифрования: {} байт/сек" \
            .format(
            encStartTime.strftime("%d.%m.%y %H:%M:%S "),
            encEndTime.strftime("%d.%m.%y %H:%M:%S "),
            str(encEndTime - encStartTime),
            fSize // (encEndTime - encStartTime).total_seconds()
        )
        # сброс прогресс-бара
        if window is not None and pbar is not None:
            self.pbar['value'] = 0
            self.window.update()

        return result

    # процедура дешифрации входного файла
    def __decrypt(self, file_in, file_out, S, w, r, mode: encrypt_mode, window, pbar):
        wb = w // 8  # размер слова в байтах
        wb2 = wb * 2
        wb3 = wb * 3
        wb4 = wb * 4
        wl = w.bit_length() - 1  # log2(w)
        p = 1 << w  # значение модуля 2**w для расчётов в раунде дешифрования

        # Получаем размер файла для дешифрования в байтах
        # (минус размер vi (wb4) в начале файла при режиме шифрования не ECB)
        fSize = Path(file_in).stat().st_size
        if mode != encrypt_mode.ECB:
            fSize = fSize - wb4

        fReadCycles = int((fSize // wb4) + (
                    1 % (fSize % wb4 + 1)))  # рассчитываем число циклов чтения блоков длиной 4*wb для дешифрования

        inputFile = open(file_in, "rb")
        outputFile = open(file_out, "wb")

        decStartTime = datetime.now()  # время начала дешифрования

        if mode != encrypt_mode.ECB:
            vi = int.from_bytes(inputFile.read(wb4),
                                "big")  # из начала дешифруемого файла читаем 4*w байта с вектором инициализации
            syncroMessage = vi  # начальное значение синхропосылки = вектор инициализации

        # инициализация прогресс-бара
        if window is not None and pbar is not None:
            self.pbar['maximum'] = fReadCycles
            self.pbar['value'] = 0
            self.window.update()

        for i in range(fReadCycles):  # Цикл по блокам в 4 слова
            # обновление значения прогресс-бара
            if window is not None and pbar is not None:
                if i % (fReadCycles // 10) == 0:
                    self.pbar['value'] += (fReadCycles // 10)
                    self.window.update()

            buffer_read = bytearray(inputFile.read(wb4))  # читаем из файла целый блок

            if mode == encrypt_mode.ECB or mode == encrypt_mode.CBC:
                buffer = buffer_read
            elif mode == encrypt_mode.CFB or mode == encrypt_mode.OFB:
                buffer = bytearray(syncroMessage.to_bytes(wb4, "big"))

            # разбиваем буфер на регистры длиной в 1 слово
            A = int.from_bytes(bytes(buffer[0:wb]), "big")
            B = int.from_bytes(bytes(buffer[wb:wb2]), "big")
            C = int.from_bytes(bytes(buffer[wb2:wb3]), "big")
            D = int.from_bytes(bytes(buffer[wb3:wb4]), "big")

            # пропускаем регистры через сеть Фейстеля
            if mode == encrypt_mode.ECB or mode == encrypt_mode.CBC:
                A, B, C, D = self.__feistel_net_dec(A, B, C, D, w, wl, p, S, r)
            else:
                A, B, C, D = self.__feistel_net_enc(A, B, C, D, w, wl, p, S, r)

            # для записи в файл разбиваем каждый зашифрованный регистр на wb байт
            A = A.to_bytes(wb, "big")
            B = B.to_bytes(wb, "big")
            C = C.to_bytes(wb, "big")
            D = D.to_bytes(wb, "big")
            out = int.from_bytes(A + B + C + D, "big")

            if mode != encrypt_mode.ECB:
                if mode == encrypt_mode.CBC:
                    buffer_write = (out ^ syncroMessage).to_bytes(wb4, "big")
                    syncroMessage = int.from_bytes(bytes(buffer_read), "big")
                elif mode == encrypt_mode.CFB or mode == encrypt_mode.OFB:
                    buffer_write = bytearray((int.from_bytes(bytes(buffer_read), "big") ^ out).to_bytes(wb4, "big"))
                    if mode == encrypt_mode.CFB:
                        syncroMessage = int.from_bytes(bytes(buffer_read), "big")
                    else:
                        syncroMessage = out
                # для записи в файл разбиваем каждый преобразованный зашифрованный регистр на wb байт
                A = bytes(buffer_write[0:wb])
                B = bytes(buffer_write[wb:wb2])
                C = bytes(buffer_write[wb2:wb3])
                D = bytes(buffer_write[wb3:wb4])

            buffer_write = (A + B + C + D)

            if i == (fReadCycles - 1):  # если блок последний, то избавляемся от набивки
                paddCount = buffer_write[-1]  # последний байт - длина набивки в байтах = значение набивки
                paddTest = 0
                for pad_i in range(paddCount):  # проверяем последние paddCount бит, все ли они равны pad_cnt
                    if buffer_write[-1 - pad_i]:
                        paddTest = paddTest + 1
                    if paddTest == paddCount:  # если все равны, то обрезаем буфер на последние pad_cnt байт
                        buffer_write = buffer_write[0: len(buffer_write) - paddCount]

            # записываем дешифрованные регистры в выходной файл
            outputFile.write(buffer_write)

        outputFile.close()
        decEndTime = datetime.now()

        result = "Начало дешифрации: {}\nКонец дешифрации: {}\nПродолжительность дешифрации: {}\nСкорость дешифрации: {} байт/сек" \
            .format(
            decStartTime.strftime("%d.%m.%y %H:%M:%S "),
            decEndTime.strftime("%d.%m.%y %H:%M:%S "),
            str(decEndTime - decStartTime),
            fSize // (decEndTime - decStartTime).total_seconds()
        )
        # сброс прогресс-бара
        if window is not None and pbar is not None:
            self.pbar['value'] = 0
            self.window.update()

        return result

    # сеть Фейстеля на r раундов шифрования
    def __feistel_net_enc(self, A, B, C, D, w, wl, p, S, r):
        B = (B + S[0]) % p
        D = (D + S[1]) % p
        for j in range(1, r + 1):
            # смешивание с ключом
            t = bit_rotation_left(self.__f(B, p), w, wl)
            u = bit_rotation_left(self.__f(D, p), w, wl)
            A = (bit_rotation_left(A ^ t, w, u % w) + S[2 * j]) % p
            C = (bit_rotation_left(C ^ u, w, t % w) + S[2 * j + 1]) % p

            # сдвиг блоков
            aa, bb, cc, dd = B, C, D, A
            A, B, C, D = aa, bb, cc, dd

        A = (A + S[2 * r + 2]) % p
        C = (C + S[2 * r + 3]) % p
        return A, B, C, D

    # сеть Фейстеля на r раундов дешифрования
    def __feistel_net_dec(self, A, B, C, D, w, wl, p, S, r):
        A = (A - S[2 * r + 2]) % p
        C = (C - S[2 * r + 3]) % p
        for j in range(1, r + 1):
            k = r - j + 1

            # обратный сдвиг блоков
            aa, bb, cc, dd = D, A, B, C
            A, B, C, D = aa, bb, cc, dd

            # выделение ключа
            t = bit_rotation_left(self.__f(B, p), w, wl)
            u = bit_rotation_left(self.__f(D, p), w, wl)
            A = bit_rotation_right((A - S[2 * k]) % p, w, u % w) ^ t
            C = bit_rotation_right((C - S[2 * k + 1]) % p, w, t % w) ^ u

        B = (B - S[0]) % p
        D = (D - S[1]) % p
        return A, B, C, D
