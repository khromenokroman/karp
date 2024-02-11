/*
 * Модуль, который работает с ARP.
 * При установке модуля, в файловой системе procfs
 * создается файл ngfw_arp, который поддерживает
 * запись. При записи в файл, происходит проверка
 * и разбор строки, которая должна содержать
 * <имя интерфейса>:<ip адрес назначения>.
 * Модуль разберет эту строку, проверит есть ли
 * такой интерфейс в системе, валидный IP или
 * нет, и создаст ARP запрос и отправит
 * в интерфейс (который был указан выше).
 * */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/neighbour.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/inet.h>
#include <net/route.h>
#include <linux/string.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define HAVE_PROC_OPS
#endif
/* размер буфера для приема сообщения */
#define PROCFS_MAX_SIZE 2048
/* имя файла profs */
#define PROCFS_FILENAME "ipv4_arp"
/* имя директории в procfs */
#define PROCFS_DIRECTORY "ngfw"

static struct proc_dir_entry *our_proc_file;
struct proc_dir_entry *out_proc_ngfw_dir;
static char procfs_buffer[PROCFS_MAX_SIZE];
static unsigned long procfs_buffer_size = 0;
static struct net_device *dev;
static struct neighbour *neigh;
static struct flowi4 fl4;
static struct rtable *rt;

/* имя интерфейса через что будем отправлять запрос*/
static char const *interface;
/* временная строка */
static char *str_tmp;
/* указатель на найденный разделитель ":" */
static char *delimiter_pos;
/* ip адрес, который хотим разрешить */
static __be32 daddr;
/* ошибка при конвертации строки в ip */
static int res;
/* позиция символа перевода строки */
int newline_pos;
/* ip адрес, который хотим разрешить в виде строки */
static char *destination_address;

/* метод который сработает при записи в /proc/ngfw_arp */
static ssize_t procfs_write(struct file *file, const char __user *buffer, size_t len, loff_t *off) {

    /* проверим чтобы строка не была больше ожидаемой */
    if (len > PROCFS_MAX_SIZE)
        procfs_buffer_size = PROCFS_MAX_SIZE;
    else
        procfs_buffer_size = len;

    /* скопируем буфер из пространства пользователя */
    if (copy_from_user(procfs_buffer, buffer, procfs_buffer_size))
        return -EFAULT;
    pr_info("The string is received: %s", procfs_buffer);

    /* проверим, содержит строка разделитель ":" или нет */
    delimiter_pos = strchr(procfs_buffer, ':');
    if (delimiter_pos != NULL) {
        /* копируем данные из буфера во временную строку */
        str_tmp = kstrdup(procfs_buffer, GFP_KERNEL);
        /* узнаем имя интерфейса */
        interface = strsep(&str_tmp, ":");
        /* узнаем цель */
        destination_address = strsep(&str_tmp, "\0");
        /* удаление символа новой строки */
        newline_pos = strcspn(destination_address, "\n");
        /* если символ найден, то заменим на конец строки */
        if (newline_pos != strlen(destination_address)) {
            destination_address[newline_pos] = '\0';
        }
        pr_info("Interface: %s", interface);
        pr_info("Destination IP: %s", destination_address);
    } else {
        pr_info("The string does not match the format. Not found delimiter");
        pr_info("You need use string in format: <name_interface>:<destination_ip>");
        return -EINVAL;
    }

    /* Привязываемся к конкретному устройству */
    /* @init_net - это глобальная переменная в ядре Linux, которая представляет
     * главную (или инициализированную) сетевую пространство имен. Это пространство
     * имен содержит все сетевые устройства, протоколы, сокеты и т. д.,
     * которые были инициализированы при загрузке системы.
     * */
    dev = dev_get_by_name(&init_net, interface);
    if (dev != NULL) {
        pr_info("Device is name: %s found", interface);

        /* преобразуем строку c целевым адресом в ip */
        res = in4_pton(destination_address, -1, (u8 * ) & daddr, -1, NULL);
        if (res != 1) {
            pr_err("Can not convert string(destination_address): %s in ip address", destination_address);
            pr_err("You need use string in format: <name_interface>:<destination_ip>");
            return -EAFNOSUPPORT;
        }

        /* Заполняем структуру для маршрутизации */
        memset(&fl4, 0, sizeof(fl4));
        fl4.flowi4_oif = dev->ifindex;
        fl4.daddr = daddr;

        /* Получаем таблицу маршрутизации */
        rt = ip_route_output_key(&init_net, &fl4);
        if (rt == NULL) {
            dev_put(dev);
            pr_err("Can not get table route");
        } else {
            /* Получим соседний узел */
            neigh = ip_neigh_gw4(dev, daddr);
            if (neigh == NULL) {
                pr_err("Can not get neigh");
            } else {
                /* отправить ARP-запрос */
                neigh_event_send(neigh, NULL);
                pr_info("Request for ip: %s on interface: %s send!\n", destination_address, interface);
            }
        }
    } else {
        pr_err("Device is name: %s NOT found", interface);
    }

    return procfs_buffer_size;
}

static int procfs_open(struct inode *inode, struct file *file) {
    try_module_get(THIS_MODULE);
    return 0;
}

static int procfs_close(struct inode *inode, struct file *file) {
    module_put(THIS_MODULE);
    return 0;
}

#ifdef HAVE_PROC_OPS
static struct proc_ops file_ops_4_our_proc_file = {
    .proc_write = procfs_write,
    .proc_open = procfs_open,
    .proc_release = procfs_close,
};
#else
static const struct file_operations file_ops_4_our_proc_file = {
        .write = procfs_write,
        .open = procfs_open,
        .release = procfs_close,
};
#endif


static int create(void) {

    pr_info("Module: NGFW_ARP is started");

    /* создание директории /proc/ngfw */
    out_proc_ngfw_dir = proc_mkdir(PROCFS_DIRECTORY, NULL);
    if (out_proc_ngfw_dir == NULL) {
        pr_err("Error: Can not create folder in /proc/%s", PROCFS_DIRECTORY);
        return -ENOMEM;
    }
    pr_info("Directory in procfs /proc/%s created\n", PROCFS_DIRECTORY);
    /* создание файла */
    our_proc_file = proc_create(PROCFS_FILENAME, 0222, out_proc_ngfw_dir, &file_ops_4_our_proc_file);
    if (our_proc_file == NULL) {
        proc_remove(out_proc_ngfw_dir);
        pr_err("Error: Can not create file in /proc/%s/%s",PROCFS_DIRECTORY, PROCFS_FILENAME);
        return -ENOMEM;
    }
    pr_info("File in procfs /proc/%s/%s created", PROCFS_DIRECTORY, PROCFS_FILENAME);
    proc_set_size(our_proc_file, 80);
    proc_set_user(our_proc_file, GLOBAL_ROOT_UID, GLOBAL_ROOT_GID);

    pr_info("Module: NGFW_ARP is load");
    return 0;
}

static void destroy(void) {
    pr_info("Module: NGFW_ARP is stop");
    proc_remove(our_proc_file);
    pr_info("File in procfs /proc/%s/%s removed\n",PROCFS_DIRECTORY, PROCFS_FILENAME);
    proc_remove(out_proc_ngfw_dir);
    pr_info("Directory in procfs /proc/%s removed\n", PROCFS_DIRECTORY);
    pr_info("Module: NGFW_ARP is unload");
}

module_init(create);
module_exit(destroy);

MODULE_AUTHOR("rkhromenok@t-argos.ru");
MODULE_DESCRIPTION("Interacts with the user through procfs, at the request of the user, sends an ARP request to resolve the iP to the MAC address");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");