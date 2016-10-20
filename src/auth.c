
#include "auth.h"

static int auth_simple_pack_unit_size = 2000;

typedef struct auth_simple_global_data {
    uint8_t local_client_id[8];
    uint32_t connection_id;
}auth_simple_global_data;

typedef struct auth_simple_local_data {
    int has_sent_header;
    char * recv_buffer;
    int recv_buffer_size;
    uint32_t recv_id;
    uint32_t pack_id;
}auth_simple_local_data;

void auth_simple_local_data_init(auth_simple_local_data* local) {
    local->has_sent_header = 0;
    local->recv_buffer = (char*)malloc(16384);
    local->recv_buffer_size = 0;
    local->recv_id = 1;
    local->pack_id = 1;
}

void * auth_simple_init_data() {
    auth_simple_global_data *global = (auth_simple_global_data*)malloc(sizeof(auth_simple_global_data));
    rand_bytes(global->local_client_id, 8);
    rand_bytes((uint8_t*)&global->connection_id, 4);
    global->connection_id &= 0xFFFFFF;
    return global;
}

obfs * auth_simple_new_obfs() {
    obfs * self = new_obfs();
    self->l_data = malloc(sizeof(auth_simple_local_data));
    auth_simple_local_data_init((auth_simple_local_data*)self->l_data);
    return self;
}

void auth_simple_dispose(obfs *self) {
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    if (local->recv_buffer != NULL) {
        free(local->recv_buffer);
        local->recv_buffer = NULL;
    }
    free(local);
    self->l_data = NULL;
    dispose_obfs(self);
}

int auth_simple_pack_data(char *data, int datalength, char *outdata) {
    unsigned char rand_len = (xorshift128plus() & 0xF) + 1;
    int out_size = rand_len + datalength + 6;
    outdata[0] = out_size >> 8;
    outdata[1] = out_size;
    outdata[2] = rand_len;
    memmove(outdata + rand_len + 2, data, datalength);
    fillcrc32((unsigned char *)outdata, out_size);
    return out_size;
}

void memintcopy_lt(void *mem, uint32_t val) {
    ((uint8_t *)mem)[0] = val;
    ((uint8_t *)mem)[1] = val >> 8;
    ((uint8_t *)mem)[2] = val >> 16;
    ((uint8_t *)mem)[3] = val >> 24;
}

int auth_simple_pack_auth_data(auth_simple_global_data *global, char *data, int datalength, char *outdata) {
    unsigned char rand_len = (xorshift128plus() & 0xF) + 1;
    int out_size = rand_len + datalength + 6 + 12;
    outdata[0] = out_size >> 8;
    outdata[1] = out_size;
    outdata[2] = rand_len;
    ++global->connection_id;
    if (global->connection_id > 0xFF000000) {
        rand_bytes(global->local_client_id, 8);
        rand_bytes((uint8_t*)&global->connection_id, 4);
        global->connection_id &= 0xFFFFFF;
    }
    time_t t = time(NULL);
    memintcopy_lt(outdata + rand_len + 2, t);
    memmove(outdata + rand_len + 2 + 4, global->local_client_id, 4);
    memintcopy_lt(outdata + rand_len + 2 + 8, global->connection_id);
    memmove(outdata + rand_len + 2 + 12, data, datalength);
    fillcrc32((unsigned char *)outdata, out_size);
    return out_size;
}

int auth_simple_client_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity) {
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    char * out_buffer = (char*)malloc(datalength * 2 + 64);
    char * buffer = out_buffer;
    char * data = plaindata;
    int len = datalength;
    int pack_len;
    if (len > 0 && local->has_sent_header == 0) {
        int head_size = get_head_size(plaindata, datalength, 30);
        if (head_size > datalength)
            head_size = datalength;
        pack_len = auth_simple_pack_auth_data((auth_simple_global_data *)self->server.g_data, data, head_size, buffer);
        buffer += pack_len;
        data += head_size;
        len -= head_size;
        local->has_sent_header = 1;
    }
    while ( len > auth_simple_pack_unit_size ) {
        pack_len = auth_simple_pack_data(data, auth_simple_pack_unit_size, buffer);
        buffer += pack_len;
        data += auth_simple_pack_unit_size;
        len -= auth_simple_pack_unit_size;
    }
    if (len > 0) {
        pack_len = auth_simple_pack_data(data, len, buffer);
        buffer += pack_len;
    }
    len = buffer - out_buffer;
    if (*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = len * 2);
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

int auth_simple_client_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity) {
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    uint8_t * recv_buffer = (uint8_t *)local->recv_buffer;
    if (local->recv_buffer_size + datalength > 16384)
        return -1;
    memmove(recv_buffer + local->recv_buffer_size, plaindata, datalength);
    local->recv_buffer_size += datalength;

    char * out_buffer = (char*)malloc(local->recv_buffer_size);
    char * buffer = out_buffer;
    while (local->recv_buffer_size > 2) {
        int length = ((int)recv_buffer[0] << 8) | recv_buffer[1];
        if (length >= 8192 || length < 7) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        if (length > local->recv_buffer_size)
            break;

        int crc = crc32((unsigned char*)recv_buffer, length);
        if (crc != -1) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        int data_size = length - recv_buffer[2] - 6;
        memmove(buffer, recv_buffer + 2 + recv_buffer[2], data_size);
        buffer += data_size;
        memmove(recv_buffer, recv_buffer + length, local->recv_buffer_size -= length);
    }
    int len = buffer - out_buffer;
    if (*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = len * 2);
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}


int auth_sha1_pack_data(char *data, int datalength, char *outdata) {
    unsigned char rand_len = (xorshift128plus() & 0xF) + 1;
    int out_size = rand_len + datalength + 6;
    outdata[0] = out_size >> 8;
    outdata[1] = out_size;
    outdata[2] = rand_len;
    memmove(outdata + rand_len + 2, data, datalength);
    filladler32((unsigned char *)outdata, out_size);
    return out_size;
}

int auth_sha1_pack_auth_data(auth_simple_global_data *global, server_info *server, char *data, int datalength, char *outdata) {
    unsigned char rand_len = (xorshift128plus() & 0x7F) + 1;
    int data_offset = rand_len + 4 + 2;
    int out_size = data_offset + datalength + 12 + OBFS_HMAC_SHA1_LEN;
    fillcrc32to((unsigned char *)server->key, server->key_len, (unsigned char *)outdata);
    outdata[4] = out_size >> 8;
    outdata[5] = out_size;
    outdata[6] = rand_len;
    ++global->connection_id;
    if (global->connection_id > 0xFF000000) {
        rand_bytes(global->local_client_id, 8);
        rand_bytes((uint8_t*)&global->connection_id, 4);
        global->connection_id &= 0xFFFFFF;
    }
    time_t t = time(NULL);
    memintcopy_lt(outdata + data_offset, t);
    memmove(outdata + data_offset + 4, global->local_client_id, 4);
    memintcopy_lt(outdata + data_offset + 8, global->connection_id);
    memmove(outdata + data_offset + 12, data, datalength);
    char hash[ONETIMEAUTH_BYTES * 2];
    ss_sha1_hmac(hash, outdata, out_size - OBFS_HMAC_SHA1_LEN, server->iv);
    memcpy(outdata + out_size - OBFS_HMAC_SHA1_LEN, hash, OBFS_HMAC_SHA1_LEN);
    return out_size;
}

int auth_sha1_client_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity) {
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    char * out_buffer = (char*)malloc(datalength * 2 + 256);
    char * buffer = out_buffer;
    char * data = plaindata;
    int len = datalength;
    int pack_len;
    if (len > 0 && local->has_sent_header == 0) {
        int head_size = get_head_size(plaindata, datalength, 30);
        if (head_size > datalength)
            head_size = datalength;
        pack_len = auth_sha1_pack_auth_data((auth_simple_global_data *)self->server.g_data, &self->server, data, head_size, buffer);
        buffer += pack_len;
        data += head_size;
        len -= head_size;
        local->has_sent_header = 1;
    }
    while ( len > auth_simple_pack_unit_size ) {
        pack_len = auth_sha1_pack_data(data, auth_simple_pack_unit_size, buffer);
        buffer += pack_len;
        data += auth_simple_pack_unit_size;
        len -= auth_simple_pack_unit_size;
    }
    if (len > 0) {
        pack_len = auth_sha1_pack_data(data, len, buffer);
        buffer += pack_len;
    }
    len = buffer - out_buffer;
    if (*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = len * 2);
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

int auth_sha1_client_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity) {
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    uint8_t * recv_buffer = (uint8_t *)local->recv_buffer;
    if (local->recv_buffer_size + datalength > 16384)
        return -1;
    memmove(recv_buffer + local->recv_buffer_size, plaindata, datalength);
    local->recv_buffer_size += datalength;

    char * out_buffer = (char*)malloc(local->recv_buffer_size);
    char * buffer = out_buffer;
    while (local->recv_buffer_size > 2) {
        int length = ((int)recv_buffer[0] << 8) | recv_buffer[1];
        if (length >= 8192 || length < 7) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        if (length > local->recv_buffer_size)
            break;

        if (checkadler32((unsigned char*)recv_buffer, length) == 0) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        int pos = recv_buffer[2] + 2;
        int data_size = length - pos - 4;
        memmove(buffer, recv_buffer + pos, data_size);
        buffer += data_size;
        memmove(recv_buffer, recv_buffer + length, local->recv_buffer_size -= length);
    }
    int len = buffer - out_buffer;
    if (*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = len * 2);
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

int auth_sha1_v2_pack_data(char *data, int datalength, char *outdata) {
    unsigned int rand_len = (datalength > 1300 ? 0 : datalength > 400 ? (xorshift128plus() & 0x7F) : (xorshift128plus() & 0x3FF)) + 1;
    int out_size = rand_len + datalength + 6;
    outdata[0] = out_size >> 8;
    outdata[1] = out_size;
    if (rand_len < 128)
    {
        outdata[2] = rand_len;
    }
    else
    {
        outdata[2] = 0xFF;
        outdata[3] = rand_len >> 8;
        outdata[4] = rand_len;
    }
    memmove(outdata + rand_len + 2, data, datalength);
    filladler32((unsigned char *)outdata, out_size);
    return out_size;
}

int auth_sha1_v2_pack_auth_data(auth_simple_global_data *global, server_info *server, char *data, int datalength, char *outdata) {
    unsigned int rand_len = (datalength > 1300 ? 0 : datalength > 400 ? (xorshift128plus() & 0x7F) : (xorshift128plus() & 0x3FF)) + 1;
    int data_offset = rand_len + 4 + 2;
    int out_size = data_offset + datalength + 12 + OBFS_HMAC_SHA1_LEN;
    const char* salt = "auth_sha1_v2";
    int salt_len = strlen(salt);
    unsigned char *crc_salt = (unsigned char*)malloc(salt_len + server->key_len);
    memcpy(crc_salt, salt, salt_len);
    memcpy(crc_salt + salt_len, server->key, server->key_len);
    fillcrc32to(crc_salt, salt_len + server->key_len, (unsigned char *)outdata);
    free(crc_salt);
    outdata[4] = out_size >> 8;
    outdata[5] = out_size;
    if (rand_len < 128)
    {
        outdata[6] = rand_len;
    }
    else
    {
        outdata[6] = 0xFF;
        outdata[7] = rand_len >> 8;
        outdata[8] = rand_len;
    }
    ++global->connection_id;
    if (global->connection_id > 0xFF000000) {
        rand_bytes(global->local_client_id, 8);
        rand_bytes((uint8_t*)&global->connection_id, 4);
        global->connection_id &= 0xFFFFFF;
    }
    memmove(outdata + data_offset, global->local_client_id, 8);
    memintcopy_lt(outdata + data_offset + 8, global->connection_id);
    memmove(outdata + data_offset + 12, data, datalength);
    char hash[ONETIMEAUTH_BYTES * 2];
    ss_sha1_hmac(hash, outdata, out_size - OBFS_HMAC_SHA1_LEN, server->iv);
    memcpy(outdata + out_size - OBFS_HMAC_SHA1_LEN, hash, OBFS_HMAC_SHA1_LEN);
    return out_size;
}

int auth_sha1_v2_client_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity) {
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    char * out_buffer = (char*)malloc(datalength * 2 + 4096);
    char * buffer = out_buffer;
    char * data = plaindata;
    int len = datalength;
    int pack_len;
    if (len > 0 && local->has_sent_header == 0) {
        int head_size = get_head_size(plaindata, datalength, 30);
        if (head_size > datalength)
            head_size = datalength;
        pack_len = auth_sha1_v2_pack_auth_data((auth_simple_global_data *)self->server.g_data, &self->server, data, head_size, buffer);
        buffer += pack_len;
        data += head_size;
        len -= head_size;
        local->has_sent_header = 1;
    }
    while ( len > auth_simple_pack_unit_size ) {
        pack_len = auth_sha1_v2_pack_data(data, auth_simple_pack_unit_size, buffer);
        buffer += pack_len;
        data += auth_simple_pack_unit_size;
        len -= auth_simple_pack_unit_size;
    }
    if (len > 0) {
        pack_len = auth_sha1_v2_pack_data(data, len, buffer);
        buffer += pack_len;
    }
    len = buffer - out_buffer;
    if (*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = len * 2);
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

int auth_sha1_v2_client_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity) {
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    uint8_t * recv_buffer = (uint8_t *)local->recv_buffer;
    if (local->recv_buffer_size + datalength > 16384)
        return -1;
    memmove(recv_buffer + local->recv_buffer_size, plaindata, datalength);
    local->recv_buffer_size += datalength;

    char * out_buffer = (char*)malloc(local->recv_buffer_size);
    char * buffer = out_buffer;
    while (local->recv_buffer_size > 2) {
        int length = ((int)recv_buffer[0] << 8) | recv_buffer[1];
        if (length >= 8192 || length < 7) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        if (length > local->recv_buffer_size)
            break;

        if (checkadler32((unsigned char*)recv_buffer, length) == 0) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        int pos = recv_buffer[2];
        if (pos < 255)
        {
            pos += 2;
        }
        else
        {
            pos = ((recv_buffer[3] << 8) | recv_buffer[4]) + 2;
        }
        int data_size = length - pos - 4;
        memmove(buffer, recv_buffer + pos, data_size);
        buffer += data_size;
        memmove(recv_buffer, recv_buffer + length, local->recv_buffer_size -= length);
    }
    int len = buffer - out_buffer;
    if (*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = len * 2);
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

int auth_sha1_v4_pack_data(char *data, int datalength, char *outdata) {
    unsigned int rand_len = (datalength > 1300 ? 0 : datalength > 400 ? (xorshift128plus() & 0x7F) : (xorshift128plus() & 0x3FF)) + 1;
    int out_size = rand_len + datalength + 8;
    outdata[0] = out_size >> 8;
    outdata[1] = out_size;
    uint32_t crc_val = crc32((unsigned char*)outdata, 2);
    outdata[2] = crc_val;
    outdata[3] = crc_val >> 8;
    if (rand_len < 128)
    {
        outdata[4] = rand_len;
    }
    else
    {
        outdata[4] = 0xFF;
        outdata[5] = rand_len >> 8;
        outdata[6] = rand_len;
    }
    memmove(outdata + rand_len + 4, data, datalength);
    filladler32((unsigned char *)outdata, out_size);
    return out_size;
}

int auth_sha1_v4_pack_auth_data(auth_simple_global_data *global, server_info *server, char *data, int datalength, char *outdata) {
    unsigned int rand_len = (datalength > 1300 ? 0 : datalength > 400 ? (xorshift128plus() & 0x7F) : (xorshift128plus() & 0x3FF)) + 1;
    int data_offset = rand_len + 4 + 2;
    int out_size = data_offset + datalength + 12 + OBFS_HMAC_SHA1_LEN;
    const char* salt = "auth_sha1_v4";
    int salt_len = strlen(salt);
    unsigned char *crc_salt = (unsigned char*)malloc(salt_len + server->key_len + 2);
    crc_salt[0] = outdata[0] = out_size >> 8;
    crc_salt[1] = outdata[1] = out_size;

    memcpy(crc_salt + 2, salt, salt_len);
    memcpy(crc_salt + salt_len + 2, server->key, server->key_len);
    fillcrc32to(crc_salt, salt_len + server->key_len + 2, (unsigned char *)outdata + 2);
    free(crc_salt);
    if (rand_len < 128)
    {
        outdata[6] = rand_len;
    }
    else
    {
        outdata[6] = 0xFF;
        outdata[7] = rand_len >> 8;
        outdata[8] = rand_len;
    }
    ++global->connection_id;
    if (global->connection_id > 0xFF000000) {
        rand_bytes(global->local_client_id, 8);
        rand_bytes((uint8_t*)&global->connection_id, 4);
        global->connection_id &= 0xFFFFFF;
    }
    time_t t = time(NULL);
    memintcopy_lt(outdata + data_offset, t);
    memmove(outdata + data_offset + 4, global->local_client_id, 4);
    memintcopy_lt(outdata + data_offset + 8, global->connection_id);
    memmove(outdata + data_offset + 12, data, datalength);
    char hash[ONETIMEAUTH_BYTES * 2];
    ss_sha1_hmac(hash, outdata, out_size - OBFS_HMAC_SHA1_LEN, server->iv);
    memcpy(outdata + out_size - OBFS_HMAC_SHA1_LEN, hash, OBFS_HMAC_SHA1_LEN);
    return out_size;
}

int auth_sha1_v4_client_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity) {
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    char * out_buffer = (char*)malloc(datalength * 2 + 4096);
    char * buffer = out_buffer;
    char * data = plaindata;
    int len = datalength;
    int pack_len;
    if (len > 0 && local->has_sent_header == 0) {
        int head_size = get_head_size(plaindata, datalength, 30);
        if (head_size > datalength)
            head_size = datalength;
        pack_len = auth_sha1_v4_pack_auth_data((auth_simple_global_data *)self->server.g_data, &self->server, data, head_size, buffer);
        buffer += pack_len;
        data += head_size;
        len -= head_size;
        local->has_sent_header = 1;
    }
    while ( len > auth_simple_pack_unit_size ) {
        pack_len = auth_sha1_v4_pack_data(data, auth_simple_pack_unit_size, buffer);
        buffer += pack_len;
        data += auth_simple_pack_unit_size;
        len -= auth_simple_pack_unit_size;
    }
    if (len > 0) {
        pack_len = auth_sha1_v4_pack_data(data, len, buffer);
        buffer += pack_len;
    }
    len = buffer - out_buffer;
    if (*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = len * 2);
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

int auth_sha1_v4_client_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity) {
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    uint8_t * recv_buffer = (uint8_t *)local->recv_buffer;
    if (local->recv_buffer_size + datalength > 16384)
        return -1;
    memmove(recv_buffer + local->recv_buffer_size, plaindata, datalength);
    local->recv_buffer_size += datalength;

    char * out_buffer = (char*)malloc(local->recv_buffer_size);
    char * buffer = out_buffer;
    while (local->recv_buffer_size > 4) {
        uint32_t crc_val = crc32((unsigned char*)recv_buffer, 2);
        if ((((uint32_t)recv_buffer[3] << 8) | recv_buffer[2]) != (crc_val & 0xffff)) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        int length = ((int)recv_buffer[0] << 8) | recv_buffer[1];
        if (length >= 8192 || length < 7) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        if (length > local->recv_buffer_size)
            break;

        if (checkadler32((unsigned char*)recv_buffer, length) == 0) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        int pos = recv_buffer[4];
        if (pos < 255)
        {
            pos += 4;
        }
        else
        {
            pos = ((recv_buffer[5] << 8) | recv_buffer[6]) + 4;
        }
        int data_size = length - pos - 4;
        memmove(buffer, recv_buffer + pos, data_size);
        buffer += data_size;
        memmove(recv_buffer, recv_buffer + length, local->recv_buffer_size -= length);
    }
    int len = buffer - out_buffer;
    if (*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = len * 2);
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}


int auth_aes128_sha1_pack_data(char *data, int datalength, char *outdata, auth_simple_local_data *local, server_info *server) {
    unsigned int rand_len = (datalength > 1200 ? 0 : local->pack_id > 4 ? (xorshift128plus() & 0x20) : datalength > 900 ? (xorshift128plus() & 0x80) : (xorshift128plus() & 0x200)) + 1;
    int out_size = rand_len + datalength + 8;
    if(datalength > 0)
        memmove(outdata + rand_len + 4, data, datalength);
    outdata[0] = out_size;
    outdata[1] = out_size >> 8;
    uint8_t *key = (uint8_t*)malloc(server->key_len + 4);
    uint8_t key_len = server->key_len + 4;
    memmove(key, server->key, server->key_len);
    memintcopy_lt(key + server->key_len, local->pack_id);

    {
        uint8_t rnd_data[rand_len];
        rand_bytes(rnd_data, rand_len);
        memmove(outdata + 4, rnd_data, rand_len);
    }

    {
        char hash[ONETIMEAUTH_BYTES * 2];
        ss_sha1_hmac_with_key(hash, outdata, 2, key, key_len);
        memmove(outdata + 2, hash, 2);
    }

    if (rand_len < 128)
    {
        outdata[4] = rand_len;
    }
    else
    {
        outdata[4] = 0xFF;
        outdata[5] = rand_len;
        outdata[6] = rand_len >> 8;
    }

    ++local->pack_id;

    {
        char hash[ONETIMEAUTH_BYTES * 2];
        ss_sha1_hmac_with_key(hash, outdata, out_size - 4, key, key_len);
        memmove(outdata + out_size - 4, hash, 4);
    }

    return out_size;
}

int auth_aes128_sha1_pack_auth_data(auth_simple_global_data *global, server_info *server, char *data, int datalength, char *outdata) {
    unsigned int rand_len = (datalength > 400 ? (xorshift128plus() & 0x200) : (xorshift128plus() & 0x400));
    int data_offset = rand_len + 16 + 4 + 4 + 7;
    int out_size = data_offset + datalength + 4;
    const char* salt = "auth_aes128_sha1";

    char * encrypt = (char*)malloc(24);
    char * encrypt_data = (char*)malloc(32);

    uint8_t *key = (uint8_t*)malloc(server->iv_len + server->key_len);
    uint8_t key_len = server->iv_len + server->key_len;
    memmove(key, server->iv, server->iv_len);
    memmove(key + server->iv_len, server->key, server->key_len);

    uint8_t rnd_data[rand_len];
    rand_bytes(rnd_data, rand_len);
    memmove(outdata + data_offset - rand_len, rnd_data, rand_len);

    if (global->connection_id > 0xFF000000) {
        rand_bytes(global->local_client_id, 8);
        rand_bytes((uint8_t*)&global->connection_id, 4);
        global->connection_id &= 0xFFFFFF;
    }
    ++global->connection_id;
    time_t t = time(NULL);
    memintcopy_lt(encrypt, t);
    memmove(encrypt + 4, global->local_client_id, 4);
    memintcopy_lt(encrypt + 8, global->connection_id);
    encrypt[12] = out_size;
    encrypt[13] = out_size >> 8;
    encrypt[14] = rand_len;
    encrypt[15] = rand_len >> 8;

    {
        uint8_t *uid = (uint8_t*)malloc(4);
        rand_bytes(uid, 4);

        char *encrypt_key_base64 = (char*)malloc(128);
        unsigned char encrypt_key[server->key_len];
        memmove(encrypt_key, server->key, server->key_len);
        base64_encode(encrypt_key, server->key_len, encrypt_key_base64);

        int base64_len = 0;
        if(server->key_len % 3 == 0)
        {
            base64_len = server->key_len / 3 * 4;
        }
        else
        {
            base64_len = (server->key_len / 3 + 1)* 4;
        }

        memmove(encrypt_key_base64 + base64_len, salt, strlen(salt));

        ss_aes_128_cbc(encrypt, encrypt_data, encrypt_key_base64);
        memmove(encrypt + 4, encrypt_data + 16, 16);
        memmove(encrypt, uid, 4);
    }

    {
        char hash[ONETIMEAUTH_BYTES * 2];
        ss_sha1_hmac_with_key(hash, encrypt, 20, key, key_len);
        memmove(encrypt + 20, hash, 4);
    }

    {
        uint8_t * rnd = (uint8_t*)malloc(1);
        rand_bytes(rnd, 1);
        memmove(outdata, rnd, 1);
        char hash[ONETIMEAUTH_BYTES * 2];
        ss_sha1_hmac_with_key(hash, (char *)rnd, 1, key, key_len);
        memmove(outdata + 1, hash, 6);

    }

    memmove(outdata + 7, encrypt, 24);
    memmove(outdata + data_offset, data, datalength);

    {
        char hash[ONETIMEAUTH_BYTES * 2];
        ss_sha1_hmac_with_key(hash, outdata, out_size - 4, server->key, server->key_len);
        memmove(outdata + out_size - 4, hash, 4);
    }

    return out_size;
}

int auth_aes128_sha1_client_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity) {
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    char * out_buffer = (char*)malloc(datalength * 2 + 4096);
    char * buffer = out_buffer;
    char * data = plaindata;
    int len = datalength;
    int pack_len;
    if (len > 0 && local->has_sent_header == 0) {
        int head_size = 1200;
        if (head_size > datalength)
            head_size = datalength;
        pack_len = auth_aes128_sha1_pack_auth_data((auth_simple_global_data *)self->server.g_data, &self->server, data, head_size, buffer);
        buffer += pack_len;
        data += head_size;
        len -= head_size;
        local->has_sent_header = 1;
    }
    while ( len > auth_simple_pack_unit_size ) {
        pack_len = auth_aes128_sha1_pack_data(data, auth_simple_pack_unit_size, buffer, local, &self->server);
        buffer += pack_len;
        data += auth_simple_pack_unit_size;
        len -= auth_simple_pack_unit_size;
    }
    if (len > 0) {
        pack_len = auth_aes128_sha1_pack_data(data, len, buffer, local, &self->server);
        buffer += pack_len;
    }
    len = buffer - out_buffer;
    if (*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = len * 2);
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

int auth_aes128_sha1_client_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity) {
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    server_info *server = (server_info*)&self->server;
    uint8_t * recv_buffer = (uint8_t *)local->recv_buffer;
    if (local->recv_buffer_size + datalength > 16384)
        return -1;
    memmove(recv_buffer + local->recv_buffer_size, plaindata, datalength);
    local->recv_buffer_size += datalength;

    uint8_t *key = (uint8_t*)malloc(server->key_len + 4);
    memmove(key, server->key, server->key_len);

    char * out_buffer = (char*)malloc(local->recv_buffer_size);
    char * buffer = out_buffer;
    while (local->recv_buffer_size > 4) {
        memintcopy_lt(key + server->key_len, local->recv_id);

        {
            char hash[ONETIMEAUTH_BYTES * 2];
            ss_sha1_hmac_with_key(hash, (char *)recv_buffer, 2, server->key, server->key_len);

            if (hash[0] != recv_buffer[2] || hash[1] != recv_buffer[3]) {
                free(out_buffer);
                local->recv_buffer_size = 0;
                return -1;
            }
        }

        int length = ((int)recv_buffer[1] << 8) + recv_buffer[0];
        if (length >= 8192 || length < 8) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        if (length > local->recv_buffer_size)
            break;

        {
            char hash[ONETIMEAUTH_BYTES * 2];
            ss_sha1_hmac_with_key(hash, (char *)recv_buffer, length - 4, server->key, server->key_len);
            if (hash[0] != recv_buffer[length - 4]
                || hash[1] != recv_buffer[length - 3]
                || hash[2] != recv_buffer[length - 2]
                || hash[3] != recv_buffer[length - 1]
                )
            {
                free(out_buffer);
                local->recv_buffer_size = 0;
                return -1;
            }
        }

        ++local->recv_id;
        int pos = recv_buffer[4];
        if (pos < 255)
        {
            pos += 4;
        }
        else
        {
            pos = ((recv_buffer[6] << 8) | recv_buffer[5]) + 4;
        }
        int data_size = length - pos - 4;
        memmove(buffer, recv_buffer + pos, data_size);
        buffer += data_size;
        memmove(recv_buffer, recv_buffer + length, local->recv_buffer_size);
    }
    int len = buffer - out_buffer;
    if (*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = len * 2);
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}
