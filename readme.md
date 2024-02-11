#### Перед сборкой модуля

```
это чтобы можно было принимать запросы которые ядро не создавало
по умолчанию должно стоять 0 - не принимать, 1 - принимать
$ echo "1" > /proc/sys/net/ipv4/conf/wlp0s20f3/arp_accept
Посмотреть текущий кеш arp
$ arp
Удалить запись из кеша
$ arp -d <ip>
```

````
$ apt install linux-headers-$(uname -r)
$ apt install build-essential
````

#### Сборка модуля
````
$ cd src
Сборка:
$ make
Очистка:
$ make clean
Просмотреть установленные модули:
$ lsmod
Загрузить модуль:
$ insmod ngfw_arp.ko
Посмотреть загрузился или нет:
$ lsmod | grep ngfw_arp
выгрузить модуль:
$ rmmod ngfw_arp
````
#### Взаимодействие
````
$ echo "eth0:192.168.88.88" > /proc/ngfw_arp
/proc/ngfw_arp при загрузке модуля будет создан файл
eth0:192.168.88.88
<имя интерфейса>:<целевой ip адрес(который надо разрешить)>
````
Просмотреть журнал
````
$ dmesg
или
$ journalctl --since=-2m
````