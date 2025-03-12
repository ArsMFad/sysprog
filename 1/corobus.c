#include "corobus.h"

#include "libcoro.h"
#include "rlist.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct data_vector {
	unsigned *data;
	size_t size;
	size_t capacity;
};

#if 1 /* Uncomment this if want to use */

/** Append @a count messages in @a data to the end of the vector. */
static void
data_vector_append_many(struct data_vector *vector,
	const unsigned *data, size_t count)
{
	if (vector->size + count > vector->capacity) {
		if (vector->capacity == 0)
			vector->capacity = 4;
		else
			vector->capacity *= 2;
		if (vector->capacity < vector->size + count)
			vector->capacity = vector->size + count;
		vector->data = realloc(vector->data,
			sizeof(vector->data[0]) * vector->capacity);
	}
	memcpy(&vector->data[vector->size], data, sizeof(data[0]) * count);
	vector->size += count;
}

/** Append a single message to the vector. */
static void
data_vector_append(struct data_vector *vector, unsigned data)
{
	data_vector_append_many(vector, &data, 1);
}

/** Pop @a count of messages into @a data from the head of the vector. */
static void
data_vector_pop_first_many(struct data_vector *vector, unsigned *data, size_t count)
{
	assert(count <= vector->size);
	memcpy(data, vector->data, sizeof(data[0]) * count);
	vector->size -= count;
	memmove(vector->data, &vector->data[count], vector->size * sizeof(vector->data[0]));
}

/** Pop a single message from the head of the vector. */
static unsigned
data_vector_pop_first(struct data_vector *vector)
{
	unsigned data = 0;
	data_vector_pop_first_many(vector, &data, 1);
	return data;
}

#endif

/**
 * One coroutine waiting to be woken up in a list of other
 * suspended coros.
 */
struct wakeup_entry {
	struct rlist base;
	struct coro *coro;
};

/** A queue of suspended coros waiting to be woken up. */
struct wakeup_queue {
	struct rlist coros;
};

#if 1 /* Uncomment this if want to use */

/** Suspend the current coroutine until it is woken up. */
static void
wakeup_queue_suspend_this(struct wakeup_queue *queue)
{
    struct wakeup_entry entry;
    entry.coro = coro_this();
    rlist_add_tail_entry(&queue->coros, &entry, base);

    // Проверяем, что есть другие активные корутины
    if (rlist_empty(&queue->coros)) {
        printf("Error: deadlock - suspension with no active coroutines\n");
        exit(-1);
    }

    printf("Coro %p suspended (queue: %p)\n", entry.coro, queue);
    coro_suspend();
    rlist_del_entry(&entry, base);
    printf("Coro %p resumed (queue: %p)\n", entry.coro, queue);
}

/** Wakeup the first coroutine in the queue. */
static void
wakeup_queue_wakeup_first(struct wakeup_queue *queue)
{
	if (rlist_empty(&queue->coros)) {
		//printf("No coros to wake up (queue: %p)\n", queue);
		return;
	}
	struct wakeup_entry *entry = rlist_first_entry(&queue->coros,
		struct wakeup_entry, base);
	//printf("Waking up coro %p (queue: %p)\n", entry->coro, queue);
	coro_wakeup(entry->coro);
}

#endif

struct coro_bus_channel {
	/** Channel max capacity. */
	size_t size_limit;
	/** Coroutines waiting until the channel is not full. */
	struct wakeup_queue send_queue;
	/** Coroutines waiting until the channel is not empty. */
	struct wakeup_queue recv_queue;
	/** Message queue. */
	struct data_vector data;
};

struct coro_bus {
	struct coro_bus_channel **channels;
	int channel_count;
};

static enum coro_bus_error_code global_error = CORO_BUS_ERR_NONE;

enum coro_bus_error_code
coro_bus_errno(void)
{
	return global_error;
}

void
coro_bus_errno_set(enum coro_bus_error_code err)
{
	global_error = err;
}

struct coro_bus *
coro_bus_new(void)
{
    struct coro_bus *bus = malloc(sizeof(struct coro_bus));
    bus->channels = NULL;
    bus->channel_count = 0;
    return bus;
}

void
coro_bus_delete(struct coro_bus *bus)
{
    for (int i = 0; i < bus->channel_count; ++i) {
        if (bus->channels[i] != NULL) {
            coro_bus_channel_close(bus, i);
        }
    }
    free(bus->channels);
    free(bus);
}

int
coro_bus_channel_open(struct coro_bus *bus, size_t size_limit)
{
    for (int i = 0; i < bus->channel_count; ++i) {
        if (bus->channels[i] == NULL) {
            bus->channels[i] = malloc(sizeof(struct coro_bus_channel));
            bus->channels[i]->size_limit = size_limit;
            rlist_create(&bus->channels[i]->send_queue.coros);
            rlist_create(&bus->channels[i]->recv_queue.coros);
            // Инициализация data_vector
            bus->channels[i]->data.data = NULL;
            bus->channels[i]->data.size = 0;
            bus->channels[i]->data.capacity = 0;
            return i;
        }
    }
    bus->channel_count++;
    bus->channels = realloc(bus->channels, bus->channel_count * sizeof(struct coro_bus_channel *));
    bus->channels[bus->channel_count - 1] = malloc(sizeof(struct coro_bus_channel));
    bus->channels[bus->channel_count - 1]->size_limit = size_limit;
    rlist_create(&bus->channels[bus->channel_count - 1]->send_queue.coros);
    rlist_create(&bus->channels[bus->channel_count - 1]->recv_queue.coros);
    // Инициализация data_vector
    bus->channels[bus->channel_count - 1]->data.data = NULL;
    bus->channels[bus->channel_count - 1]->data.size = 0;
    bus->channels[bus->channel_count - 1]->data.capacity = 0;
    return bus->channel_count - 1;
}

void
coro_bus_channel_close(struct coro_bus *bus, int channel)
{
    if (channel < 0 || channel >= bus->channel_count || bus->channels[channel] == NULL) {
        return;
    }
    struct coro_bus_channel *ch = bus->channels[channel];

    printf("Closing channel %d\n", channel);

    // Пробуждаем все корутины в очереди отправки
    while (!rlist_empty(&ch->send_queue.coros)) {
        struct wakeup_entry *entry = rlist_shift_entry(&ch->send_queue.coros, struct wakeup_entry, base);
        coro_wakeup(entry->coro);
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);  // Устанавливаем ошибку
    }

    // Пробуждаем все корутины в очереди получения
    while (!rlist_empty(&ch->recv_queue.coros)) {
        struct wakeup_entry *entry = rlist_shift_entry(&ch->recv_queue.coros, struct wakeup_entry, base);
        coro_wakeup(entry->coro);
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);  // Устанавливаем ошибку
    }

    // Освобождаем память
    free(ch->data.data);
    free(ch);
    bus->channels[channel] = NULL;
}

int
coro_bus_send(struct coro_bus *bus, int channel, unsigned data)
{
    if (channel < 0 || channel >= bus->channel_count || bus->channels[channel] == NULL) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }
    struct coro_bus_channel *ch = bus->channels[channel];

    //printf("Trying to send data %u to channel %d (size: %zu, limit: %zu)\n",
           //data, channel, ch->data.size, ch->size_limit);

    while (coro_bus_try_send(bus, channel, data) != 0) {
        if (bus->channels[channel] == NULL) {
            // Канал был закрыт
            coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
            return -1;
        }
        //printf("Channel %d is full, suspending coro %p\n", channel, coro_this());
        wakeup_queue_suspend_this(&ch->send_queue);
        //printf("Coro %p resumed, checking channel %d (size: %zu, limit: %zu)\n",
               //coro_this(), channel, ch->data.size, ch->size_limit);
    }

    //printf("Data %u sent to channel %d (size: %zu)\n", data, channel, ch->data.size);

    // Пробуждаем только если есть корутины в очереди получателей
    if (!rlist_empty(&ch->recv_queue.coros)) {
        wakeup_queue_wakeup_first(&ch->recv_queue);
    }

    return 0;
}


int
coro_bus_try_send(struct coro_bus *bus, int channel, unsigned data)
{
    if (channel < 0 || channel >= bus->channel_count || bus->channels[channel] == NULL) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }
    struct coro_bus_channel *ch = bus->channels[channel];

    if (ch->data.size >= ch->size_limit) {
        coro_bus_errno_set(CORO_BUS_ERR_WOULD_BLOCK);
        return -1;
    }

    data_vector_append(&ch->data, data);
    //printf("Data %u sent to channel %d (size: %zu)\n", data, channel, ch->data.size);

    // Пробуждаем только если есть корутины в очереди получателей
    if (!rlist_empty(&ch->recv_queue.coros)) {
        wakeup_queue_wakeup_first(&ch->recv_queue);
    }

    return 0;
}

int
coro_bus_recv(struct coro_bus *bus, int channel, unsigned *data)
{
    if (channel < 0 || channel >= bus->channel_count || bus->channels[channel] == NULL) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }
    struct coro_bus_channel *ch = bus->channels[channel];

    //printf("Trying to recv data from channel %d (size: %zu)\n", channel, ch->data.size);

    while (coro_bus_try_recv(bus, channel, data) != 0) {
        if (bus->channels[channel] == NULL) {
            // Канал был закрыт
            coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
            return -1;
        }
        //printf("Channel %d is empty, suspending coro %p\n", channel, coro_this());
        wakeup_queue_suspend_this(&ch->recv_queue);
        //printf("Coro %p resumed, checking channel %d (size: %zu)\n",
               //coro_this(), channel, ch->data.size);
    }

    //printf("Data %u received from channel %d (size: %zu)\n", *data, channel, ch->data.size);

    // Пробуждаем только если есть корутины в очереди отправителей
    if (!rlist_empty(&ch->send_queue.coros)) {
        wakeup_queue_wakeup_first(&ch->send_queue);
    }

    return 0;
}

int
coro_bus_try_recv(struct coro_bus *bus, int channel, unsigned *data)
{
    if (channel < 0 || channel >= bus->channel_count || bus->channels[channel] == NULL) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }
    struct coro_bus_channel *ch = bus->channels[channel];

    if (ch->data.size == 0) {
        coro_bus_errno_set(CORO_BUS_ERR_WOULD_BLOCK);
        return -1;
    }

    *data = data_vector_pop_first(&ch->data);
    //printf("Data %u received from channel %d (size: %zu)\n", *data, channel, ch->data.size);

    // Пробуждаем только если есть корутины в очереди отправителей
    if (!rlist_empty(&ch->send_queue.coros)) {
        wakeup_queue_wakeup_first(&ch->send_queue);
    }

    return 0;
}


#if NEED_BROADCAST

int
coro_bus_broadcast(struct coro_bus *bus, unsigned data)
{
    int sent = 0;
    for (int i = 0; i < bus->channel_count; ++i) {
        if (bus->channels[i] != NULL) {
            while (coro_bus_try_send(bus, i, data) != 0) {
                // Если канал полон, приостанавливаем корутину
                wakeup_queue_suspend_this(&bus->channels[i]->send_queue);
            }
            sent++;
        }
    }
    if (sent == 0) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }
    return 0;
}

int
coro_bus_try_broadcast(struct coro_bus *bus, unsigned data)
{
    int sent = 0;
    for (int i = 0; i < bus->channel_count; ++i) {
        if (bus->channels[i] != NULL) {
            if (coro_bus_try_send(bus, i, data) != 0) {
                // Если хотя бы один канал полон, возвращаем ошибку
                coro_bus_errno_set(CORO_BUS_ERR_WOULD_BLOCK);
                return -1;
            }
            sent++;
        }
    }
    if (sent == 0) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }
    return 0;
}
#endif

#if NEED_BATCH

int
coro_bus_send_v(struct coro_bus *bus, int channel, const unsigned *data, unsigned count)
{
    if (channel < 0 || channel >= bus->channel_count || bus->channels[channel] == NULL) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }
    struct coro_bus_channel *ch = bus->channels[channel];

    unsigned sent = 0;
    while (sent < count) {
        unsigned to_send = count - sent;
        if (to_send > ch->size_limit - ch->data.size) {
            to_send = ch->size_limit - ch->data.size;
        }
        if (to_send == 0) {
            // Если канал полон, приостанавливаем корутину
            wakeup_queue_suspend_this(&ch->send_queue);
            continue;
        }
        data_vector_append_many(&ch->data, data + sent, to_send);
        sent += to_send;
        // Пробуждаем корутины в очереди получателей
        if (!rlist_empty(&ch->recv_queue.coros)) {
            wakeup_queue_wakeup_first(&ch->recv_queue);
        }
    }
    return sent;
}

int
coro_bus_try_send_v(struct coro_bus *bus, int channel, const unsigned *data, unsigned count)
{
    if (channel < 0 || channel >= bus->channel_count || bus->channels[channel] == NULL) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }
    struct coro_bus_channel *ch = bus->channels[channel];

    unsigned sent = 0;
    while (sent < count && ch->data.size < ch->size_limit) {
        unsigned to_send = count - sent;
        if (to_send > ch->size_limit - ch->data.size) {
            to_send = ch->size_limit - ch->data.size;
        }
        data_vector_append_many(&ch->data, data + sent, to_send);
        sent += to_send;
        // Пробуждаем корутины в очереди получателей
        if (!rlist_empty(&ch->recv_queue.coros)) {
            wakeup_queue_wakeup_first(&ch->recv_queue);
        }
    }
    if (sent == 0) {
        coro_bus_errno_set(CORO_BUS_ERR_WOULD_BLOCK);
        return -1;
    }
    return sent;
}

int
coro_bus_recv_v(struct coro_bus *bus, int channel, unsigned *data, unsigned capacity)
{
    if (channel < 0 || channel >= bus->channel_count || bus->channels[channel] == NULL) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }
    struct coro_bus_channel *ch = bus->channels[channel];

    unsigned received = 0;
    while (received < capacity) {
        unsigned to_receive = capacity - received;
        if (to_receive > ch->data.size) {
            to_receive = ch->data.size;
        }
        if (to_receive == 0) {
            // Если канал пуст, приостанавливаем корутину
            wakeup_queue_suspend_this(&ch->recv_queue);
            continue;
        }
        data_vector_pop_first_many(&ch->data, data + received, to_receive);
        received += to_receive;
        // Пробуждаем корутины в очереди отправителей
        if (!rlist_empty(&ch->send_queue.coros)) {
            wakeup_queue_wakeup_first(&ch->send_queue);
        }
    }
    return received;
}

int
coro_bus_try_recv_v(struct coro_bus *bus, int channel, unsigned *data, unsigned capacity)
{
    if (channel < 0 || channel >= bus->channel_count || bus->channels[channel] == NULL) {
        coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
        return -1;
    }
    struct coro_bus_channel *ch = bus->channels[channel];

    unsigned received = 0;
    while (received < capacity && ch->data.size > 0) {
        unsigned to_receive = capacity - received;
        if (to_receive > ch->data.size) {
            to_receive = ch->data.size;
        }
        data_vector_pop_first_many(&ch->data, data + received, to_receive);
        received += to_receive;
        // Пробуждаем корутины в очереди отправителей
        if (!rlist_empty(&ch->send_queue.coros)) {
            wakeup_queue_wakeup_first(&ch->send_queue);
        }
    }
    if (received == 0) {
        coro_bus_errno_set(CORO_BUS_ERR_WOULD_BLOCK);
        return -1;
    }
    return received;
}

#endif
