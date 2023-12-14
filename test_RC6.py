from RC6 import rc6
import random


# ТЕСТИРОВАНИЕ ШИФРОВАНИЯ/ДЕШИФРОВАНИЯ ПО АЛГОРИТМУ RC6
# ======================================================
# генерируем ключ длиной N бит
N = 64
chars_dict = list("qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM~!@#$%^&*()_+|}{:?><[];.,=")
secret_key = ""
for i in range(N // 8):
    secret_key = secret_key + chars_dict[random.randint(0, len(chars_dict) - 1)]

# устанавливаем режим шифрования/дешифрования
mode = "ECB"
#mode = "CBC"
#mode = "CFB"
#mode = "OFB"

# указываем файл для обработки
filename = "test_file.jpg"
#filename = "test_video.avi"
file_enc_in = filename
file_enc_out = file_enc_in + ".enc"
file_dec_in = file_enc_out
file_dec_out = file_dec_in + ".dec"

w = 64  # Устанавливаем длину слова в блоке шифрования в битах
r = 20  # Устанавливаем количество раундов шифрования

# шифруем файл
encrypting = rc6(file_in=file_enc_in, file_out=file_enc_out, key=secret_key, mode=mode, block=w, rounds=r)
enc_result = encrypting.transform("encrypt")
print(enc_result)

mode = "ECB"
#mode = "CBC"
#mode = "CFB"
#mode = "OFB"

# дешифруем файл
decrypting = rc6(file_in=file_dec_in, file_out=file_dec_out, key=secret_key, mode=mode, block=w, rounds=r)
dec_result = decrypting.transform("decrypt")
print(dec_result)
