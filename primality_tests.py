import random


# функция, вызывающая один из трёх тестов на простоту, в зависимости от выбранного параметра
def prime_test(n, primTest, primTestRounds):
    result = 0
    if primTest == "FERMAT":
        result = fermat_prime_test(n, primTestRounds)
    if primTest == "MILLER-RABIN":
        result = mr_prime_test(n, primTestRounds)
    if primTest == "SOLOVAY-STRASSEN":
        result = ss_prime_test(n, primTestRounds)
    return result


# проверка простоты числа по методу Ферма
# если число предположительно простое, то результат 1, иначе 0
def fermat_prime_test(n, primTestRounds):
    if n % 2 == 0:
        return 0
    for i in range(primTestRounds):
        a = random.randint(1, n - 1)
        if pow(a, n - 1, n) != 1:
            return 0
    return 1


# проверка простоты числа по методу Соловея-Штрассена
# https://ru.wikipedia.org/wiki/Тест_Соловея_—_Штрассена
# если число предположительно простое, то результат 1, иначе 0
def ss_prime_test(n, primTestRounds):
    for _ in range(primTestRounds):
        a = random.randint(2, n - 1)
        x = jacobi(a, n)
        y = pow(a, (n - 1) // 2, n)
        if x == 0 or y != x % n:
            return 0
    return 1
# вычисление символа Якоби для теста С-С
def jacobi(a, n):
    result = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            if n % 8 == 3 or n % 8 == 5:
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n
    if n == 1:
        return result
    else:
        return 0


# проверка простоты числа по алгоритму Миллера-Рабина
# (https://ru.wikipedia.org/wiki/Тест_Миллера_—_Рабина)
# если число предположительно простое, то результат 1, иначе 0
def mr_prime_test(n, primTestRounds):
    if n % 2 == 0:
        return 0
    s = 0
    t = n - 1
    while t % 2 == 0:
        s = s + 1
        t = t // 2
    for A in range(primTestRounds):
        a = random.randint(2, n - 1)
        x = pow(a, t, n)
        if x == 1 or x == n - 1:
            continue
        for B in range(s - 1):
            x = pow(x, 2, n)
            if x == 1:
                return 0
            if x == n - 1:
                break
        return 0
    return 1
