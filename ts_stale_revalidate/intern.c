#include <stdlib.h>
#include <string.h>
#include "trie.h"
#include "intern.h"
#include "common.h"

int intern_init(struct intern *pool)
{
    pool->trie = trie_create();
    return pool->trie == NULL ? -1 : 0;
}


static int visitor_free(const char *key, unsigned int sec,void *data, void *arg)
{
    (void) key;
    (void) arg;
    (void) sec;
    free(data);
    return 0;
}


int intern_free(struct intern *pool)
{
    trie_visit(pool->trie, "", visitor_free, NULL);
    return trie_free(pool->trie);
}


static void *inserter(const char *key, void *data, void *arg)
{
    char **dup = (char **)arg;
    if (data == NULL) {
        *dup = (char *)malloc(strlen(key) + 1);
        if (*dup != NULL)
            strcpy(*dup, key);
        return *dup;
    } else {
        return (*dup = (char *)data);
    }
}


const char *intern(struct intern *pool, const char *string,unsigned int sec)
{
    char *canonical = NULL;
    trie_replace(pool->trie, string, inserter, &canonical,sec);
    return canonical;
}


const char *intern_soft(struct intern *pool, const char *string)
{
    return (const char *)trie_search(pool->trie, string);
}


unsigned int intern_soft_sec(struct intern *pool, const char *string)
{
    return trie_search_sec(pool->trie, string);
}


size_t intern_count(struct intern *pool)
{
    return trie_count(pool->trie, "");
}
