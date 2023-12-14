# Модуль вычисления ассиметричных ключей по схеме Эль-Гамаля. Используя функции модуля, клиент-инициатор (Alice)
# может рассчитать компоненты (y, p, g) открытого ключа и закрытый ключ дешифрации x.
# В свою очередь, абонент-ответчик (Bob), получив от клиента-инициатора открытый ключ (y, p, g), может сгенерировать
# секретный сессионный ключ m, секретный ключ шифрования k и передать клиенту-инициатору ключ m,
# зашифрованный на ключе k, в виде компонент a и b шифротекста.
import random
from primality_tests import *


# класс "Ключи Alice"
class AliceKeys:
    def __init__(self, y, p, g, x):
        self.y = y
        self.p = p
        self.g = g
        self.x = x


# класс "Ключи и шифротекст Bob"
class BobKeysCipherText:
    def __init__(self, k, a, b):
        self.k = k
        self.a = a
        self.b = b


# вычисление НОД по алгоритму Евклида
def gcd(a, b):
    while b > 0:
        a, b = b, a % b
    return a


# вычисление случайного N-битного простого числа, у которого phi(p)=p-1 и phi(p) раскладывается на 2 простых множителя
# (для упрощения поиска первообразного корня g), где phi(p) - функция Эйлера
# для этого вычислим безопасное простое число p - такое, что есть целое число q, для которого p=2*q+1
# (https://cyberleninka.ru/article/n/prakticheskie-aspekty-generatsii-klyuchey-dlya-kriptosistemy-el-gamalya/viewer,
# https://ru.wikipedia.org/wiki/Безопасное_простое_число, https://eprint.iacr.org/2003/186.pdf)
def safe_prime(bits_length, primTest, primTestRounds):
    p_res = 0
    p = 0
    q = 0
    while p_res == 0:
        q_res = 0
        while q_res == 0:
            # генерируем (N-1)-битное целое число - источник
            q = random.randint(pow(2, bits_length - 2), pow(2, bits_length - 1) - 1)
            q_res = prime_test(q, primTest, primTestRounds)
        p = 2 * q + 1  # это число будет уже N-битным
        p_res = prime_test(p, primTest, primTestRounds)
    return p


# вычисление первообразного корня
# т.к. phi(p)=p-1 и имеет только 2 простых сомножителя (2 и q=(p-1)/2), то достаточно проверить,
# что (g^q mod p)<>1, где g - кандидат на роль первообразного корня
# (https://ru.wikipedia.org/wiki/Первообразный_корень_(теория_чисел))
def primitive_root(p):
    q = (p - 1) // 2
    g = 0
    res = 1
    while res == 1:
        g = random.randint(2, p - 1)  # получили случайного кандидата на первообразный корень
        res = pow(g, q, p)
    return g


# вычисление секретного ключа дешифрации x и дополнительного ключа y
# после расчёта безопасного простого числа p и нахождения его первообразного корня g;
# формирование открытого ключа
# (https://ru.wikipedia.org/wiki/Схема_Эль-Гамаля)
def get_open_keys(p, g):
    x = random.randint(2, p - 2)
    y = pow(g, x, p)
    return [y, p, g, x]


# генерация случайного текстового сессионного ключа
def generate_session_key(key_len):
    chars_dict = list("qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM~!@#$%^&*()_+|}{:?><[];.,=")
    session_key = ""
    for i in range(key_len):
        session_key = session_key + chars_dict[random.randint(0, len(chars_dict) - 1)]
    return session_key


# формирование компонентов открытого ключа и секретного ключа дешифрации x для Alice
# будет использован тест на простоту primTest с количеством раундов primTestRounds
def get_keys_alice(bits_length, primTest, primTestRounds):
    p = safe_prime(bits_length, primTest, primTestRounds)  # получили безопасное простое число
    g = primitive_root(p)  # получили первообразный корень
    openKeys = get_open_keys(p, g)  # получили секретный ключ шифрования и открытый ключ
    return AliceKeys(openKeys[0], openKeys[1], openKeys[2], openKeys[3])


# вычисление секретного ключа шифрования k, открытой компоненты №1 шифротекста a,
# секретного сессионного ключа m - в открытом виде и зашифрованного сессионого ключа
# на вход передаём открытый ключ Alice и длину текстового сессионного ключа в символах
# (https://ru.wikipedia.org/wiki/Схема_Эль-Гамаля)
def el_gamal_encrypt(alice_key: AliceKeys, session_key_length: object, primTest, primTestRounds) -> object:
    y = alice_key.y
    p = alice_key.p
    g = alice_key.g
    msg = generate_session_key(session_key_length)
    msg_chars = list(msg)  # получаем случайный сессионный ключ в текстовом виде
    b_chars = []  # список для хранения b(i) - зашифрованных символов сессионного ключа
    k = 0
    k_res = 0
    while k_res == 0:
        k = random.randint(2, p - 2)  # получаем секретный ключ шифрования
        # проверяем, что ключ - простое число, взаимно простое с p-1, т.е. НОД(k, p-1) = 1
        k_res = prime_test(k, primTest, primTestRounds) * gcd(k, p - 1)
    a = pow(g, k, p)  # вычисляем a - открытую компоненту №1 шифротекста
    for msg_char in msg_chars:
        m = ord(msg_char)  # представляем каждый символ m в виде кода UTF (да, можно шифровать иероглифы и эмодзи :)
        b = ((m % p) * (pow(y, k, p))) % p
        b_chars.append(b)
    encrypted_keys = BobKeysCipherText(k, a, b_chars)
    return [msg, encrypted_keys]


# дешифрация участником-инициатором зашифрованного сессионного ключа с помощью секретного ключа дешифрации
# (https://ru.wikipedia.org/wiki/Схема_Эль-Гамаля)
def el_gamal_decrypt(a, enc_msg, x, p):
    dec_msg_char = []
    for b in enc_msg:
        m = ((b % p) * pow(a, p - 1 - x, p)) % p
        dec_msg_char.append(chr(m))
    return "".join(dec_msg_char)
