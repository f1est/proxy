**Для загрузки проекта, используйте следующую команду:**
```sh
git clone https://github.com/f1est/proxy.git --recurse-submodules
```

## Зависимости
Для сборки проекта, потребуются следующие библиотеки:

- libevent      (wget https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz)
- libconfig     (git clone https://github.com/hyperrealm/libconfig.git)
- openssl       (wget https://www.openssl.org/source/openssl-1.0.2l.tar.gz)


## Установка
Чтобы не тянуть с собой libevent, собираем проект с этой библиотекой статикой. Для этого в Makefile исправить следующие строки:
LIBEVENT_PATH = /путь/к/архивам/ libevent_openssl.a и libevent.a
LIBEVENT_INCLUDE_PATH = /путь/к/заголовочным/файлам/ libevent

далее выполнить команду:
```sh
make
```

## Запуск

```sh
./embediProxy -h

 Usage: ./embediProxy [options]
 Options are:
        -d        Do not daemonize (run in foreground).
        -c FILE   Use an alternate configuration file.
        -h        Display this usage information.
```

конфиг файл лежит в директории test/example.cfg

пример запуска:
```sh
./embediProxy -d -c test/example.cfg
```

## Конфиг файл
**Основные параметры:**

**listen_address**  - IP-адрес и порт на котором слушаем входящие соединения. (Принимаемое значение строка: "ip_address:port")

**connect_address** - IP-адрес и порт на котором слушает входящие соединения приложение (сервер). (Принимаемое значение строка: "ip_address:port")

**max_listeners**   - максимальное число одновременных соединений (максимальное число сессий). (Принимаемое значение integer)

**user**            - ID или Name пользователя от которого будет запускаться приложение при попытке запуска от root'a. (Принимаемое значение integer/строка: user = "1000", user = 1000 ,user = "username")

**group**           - по аналогии параметру user

**core_module**     - включает/выключает web_tool_kit. В выключенном состоянии трафик просто перенаправляется между клиентом (браузер) и сервером (приложение). (Принимаемое значение true/false)

**http_server_timeout**     - таймаут. Время которое прокси ождидает ответа от сервера. (Принимаемое значение integer)

**pid_file**        - Путь к файлу в котором будет храниться ID-процесса при запуске без параметра -d (Принимаемое значение строка: "путь в кавычках")

## Следующие параметры для работы с загаловками Set-Cookie и Cookie:

**max_length_of_cookie**    - максимальная длина куки в байтах (Принимаемое значение integer)

**max_num_of_cookies**      - максимальное количество кук в запросе (Принимаемое значение integer)

**expires_of_cookie**       - время жизни куки ((Принимаемое значение integer)


