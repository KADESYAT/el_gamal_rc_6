import el_gamal as eg


# тестовые вызовы функций

#   расчёт ключей для клиента-инициатора
clientKeys = eg.get_keys_alice(64, "SOLOVAY-STRASSEN", 100)
#clientKeys = eg.get_keys_alice(64, "MILLER-RABIN", 100)
print("y = {}, p = {}, g = {}, x = {}".format(clientKeys.y, clientKeys.p, clientKeys.g, clientKeys.x))

#   расчёт ключей для абонента, получение открытого и зашифрованного сессионного ключа
abonentKeys = eg.el_gamal_encrypt(clientKeys, 64, "FERMAT", 100)
m = abonentKeys[0]
k_key = abonentKeys[1].k
a_component = abonentKeys[1].a
b_component = abonentKeys[1].b
print("Shared session key (to encrypt): {}\nBob's private cryptgraphic key: {}\nCiphertext components: a = {}, b = {}"
      .format(m, k_key, a_component, b_component))

#   дешифрация зашифрованного сессионного ключа клиентом-инициатором
decoded_m = eg.el_gamal_decrypt(a_component, b_component, clientKeys.x, clientKeys.p)
print("Decoded ciphertext:", decoded_m)
