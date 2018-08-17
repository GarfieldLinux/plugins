#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <dirent.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ts/ts.h>

#include "trie.h"
#include "intern.h"
#include "common.h"

#define CONFIG_TMOUT 6000

#define DEFAULT_REVALIDATE_TIME  86400*15

#define BUF_LEN  8192

#define URL_LEN 8192
#define HOST_LEN 256

#define SUCCESS_INFO_STATUS_CODE  1002
#define SUCCESS_STATUS_CODE 1001
#define FAIL_STATUS_CODE  1000

#define RULE_DIRECTORY_HOST "http://ts.stale.revalidate.com/"
#define RULE_DIRECTORY_HOST_LEN 31

#define RULE_DIR_PATH "var/stale_revalidate"

#define RULE_FILE_NAME "rule_url"

TSFile reset_fp_init = NULL;
TSFile rule_fp = NULL;

pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

struct intern pool;


struct intern pool_tmp;

static time_t
get_date_from_cached_hdr(TSHttpTxn txn)
{
  TSMBuffer buf;
  TSMLoc hdr_loc, date_loc;
  time_t date = 0;

  if (TSHttpTxnCachedRespGet(txn, &buf, &hdr_loc) == TS_SUCCESS) {
    date_loc = TSMimeHdrFieldFind(buf, hdr_loc, TS_MIME_FIELD_DATE, TS_MIME_LEN_DATE);
    if (date_loc != TS_NULL_MLOC) {
      date = TSMimeHdrFieldValueDateGet(buf, hdr_loc, date_loc);
      TSHandleMLocRelease(buf, hdr_loc, date_loc);
    }
    TSHandleMLocRelease(buf, TS_NULL_MLOC, hdr_loc);
  }

  return date;
}

void get_url(TSHttpTxn txnp, char **url, int *url_length)//after using this function to free "url"
{

	*url = TSHttpTxnEffectiveUrlStringGet(txnp, url_length);
	if(!*url) {
           ERROR_LOG("get_url: couldn`t retrieve request url");
           return;
    }

	return;
}

void get_url_param(char *url, int url_length, const char *param, char **url_param, int *url_param_length)
{
	if(!param)
		return;// param_info;
	
	char *p = strstr(url, param);
	if(p && ((*url_param_length = (url_length - (strlen(url) - strlen(p + 1)))) > 0)) {
		*url_param = p + 1;
	}
			
	return ;//param_info;
}

void get_restore_url(TSHttpTxn txnp, char **url, int *url_length)//after using this function ---> free "url"
{
	*url = TSHttpTxnStoreUrlGet(txnp, url_length);
	if(!*url) {
           ERROR_LOG("couldn`t retrieve Store url");
           return;
    }
	return;
}

enum
{
	Rule_none,
	Rule_dir_info,
	Rule_dir_add,
	Rule_dir_cancel,
	Rule_dir_none
};

int check_request_rule(TSHttpTxn txnp,const char *url, int url_len)
{
	if(url_len < RULE_DIRECTORY_HOST_LEN)
		return Rule_none;

	if(strncmp(url,RULE_DIRECTORY_HOST, RULE_DIRECTORY_HOST_LEN) == 0) {
		if((url_len >= RULE_DIRECTORY_HOST_LEN + 15) && (strncmp(url + RULE_DIRECTORY_HOST_LEN, "rule_dir_cancel", 15) == 0)) {
			return Rule_dir_cancel;
		} else if((url_len >= RULE_DIRECTORY_HOST_LEN + 12) && (strncmp(url + RULE_DIRECTORY_HOST_LEN, "rule_dir_add", 12) == 0)) {
		        return Rule_dir_add;
	        } else if((url_len >= RULE_DIRECTORY_HOST_LEN + 13) && (strncmp(url + RULE_DIRECTORY_HOST_LEN, "rule_dir_info", 13) == 0)) 
			return  Rule_dir_info;
	        else { 
			return Rule_dir_none;
               }
	}

	return Rule_none;
}


int visitor_print(const char *key, unsigned int sec, void *data, void *arg)
{
	(void) data;
	(void) arg;
	DEBUG_LOG("key:%s data:%s sec:%d\n", key,(char*)data,sec);
	return 0;
}


int visitor_copy(const char *key, unsigned int sec, void *data, void *arg)
{
	(void) data;
	(void) arg;
	DEBUG_LOG("pool_tmp key:%s data:%s sec:%d\n", key,(char*)data,sec);
	intern(&pool_tmp, key,sec);
	return 0;
}

int visitor_copy_pool(const char *key, unsigned int sec, void *data, void *arg)
{
	(void) data;
	(void) arg;
	DEBUG_LOG("key:%s data:%s sec:%d\n", key,(char*)data,sec);
	if(sec > 0)
	   intern(&pool, key,sec);
	return 0;
}


int visitor_flush(const char *key, unsigned int sec, void *data, void *arg)
{
	(void) data;
	(void) arg;
 
	if((sec > 0) && (strncmp("http://",key,7) == 0 ) ) {
	   char mes[URL_LEN + 128] = {0};
	   snprintf(mes, sizeof(mes) - 1, "%s\t%u\n",key, sec);
           TSfwrite(reset_fp_init, mes, strlen(mes));
	   DEBUG_LOG("flush data:%s to disk\n", mes);
	}else{
	   char mess[URL_LEN + 128] = {0};
	   snprintf(mess, sizeof(mess) - 1, "%s\t%u\n",key, sec);
	   DEBUG_LOG("Error data:%s",mess);
	   ERROR_LOG("Error data:%s",mess);
	}
	return 0;
}



int split_str(const char* url , char* str,char c )
{
	if(url &&  (strncmp(url,"http://",7) == 0) ) {
		char *p = NULL ;
		p = strrchr(url, '/');
		if(p) {
			memcpy(str,url,p - url + 1);
		}
	}

	return 0;
}


/**
 * Set a header to a specific value. This will avoid going to through a
 * remove / add sequence in case of an existing header.
 * but clean.
 *
 * From background_fetch.cc
 */
static bool
set_header(TSMBuffer bufp, TSMLoc hdr_loc, const char *header, int len, const char *val, int val_len)
{
   if (!bufp || !hdr_loc || !header || len <= 0 || !val || val_len <= 0) {
      return false;
   }

   bool ret         = false;
   TSMLoc field_loc = TSMimeHdrFieldFind(bufp, hdr_loc, header, len);

   if (!field_loc) {
      // No existing header, so create one
      if (TS_SUCCESS == TSMimeHdrFieldCreateNamed(bufp, hdr_loc, header, len, &field_loc)) {
         if (TS_SUCCESS == TSMimeHdrFieldValueStringSet(bufp, hdr_loc, field_loc, -1, val, val_len)) {
            TSMimeHdrFieldAppend(bufp, hdr_loc, field_loc);
            ret = true;
         }
         TSHandleMLocRelease(bufp, hdr_loc, field_loc);
      }
   } else {
      TSMLoc tmp = NULL;
      bool first = true;
      while (field_loc) {
         if (first) {
            first = false;
            if (TS_SUCCESS == TSMimeHdrFieldValueStringSet(bufp, hdr_loc, field_loc, -1, val, val_len)) {
               ret = true;
            }
         } else {
            TSMimeHdrFieldDestroy(bufp, hdr_loc, field_loc);
         }
         tmp = TSMimeHdrFieldNextDup(bufp, hdr_loc, field_loc);
         TSHandleMLocRelease(bufp, hdr_loc, field_loc);
         field_loc = tmp;
      }
   }
  return ret;
}

int check_get_method(TSHttpTxn txnp)
{
	TSMBuffer req_bufp;
	TSMLoc req_loc;
	int ret = -1;

	if(TSHttpTxnClientReqGet (txnp, &req_bufp, &req_loc) == TS_SUCCESS) {
		int method_len;
		const char *method = TSHttpHdrMethodGet(req_bufp, req_loc, &method_len);
		if(strncmp(method, TS_HTTP_METHOD_GET, TS_HTTP_LEN_GET) == 0) {
                   ret =1;
		}
		TSHandleMLocRelease (req_bufp, TS_NULL_MLOC, req_loc);
	}
	return ret;
}



static int
rule_handler(TSCont contp, TSEvent event, void *edata)
{
	TSHttpTxn txnp = (TSHttpTxn)edata;
	int status;
	time_t date = 0, now = 0;
	TSEvent reenable = TS_EVENT_HTTP_CONTINUE;

	switch (event) {
		case TS_EVENT_HTTP_POST_REMAP:
			{
				if(check_get_method(txnp) < 0)
					break ;

				int return_status = FAIL_STATUS_CODE;
				char *url_cmd = NULL;
				int url_cmd_length;
				get_url(txnp, &url_cmd, &url_cmd_length);
				if(!url_cmd) {
					break;
				}	
				if(url_cmd_length >= URL_LEN) {
					TSfree(url_cmd);
					break;
				}

				switch (check_request_rule(txnp,url_cmd, url_cmd_length))
				{
					case Rule_dir_info:
						{
							return_status = SUCCESS_INFO_STATUS_CODE;
							TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);
							reenable = TS_EVENT_HTTP_ERROR;
							TSHttpTxnSetHttpRetStatus(txnp, (TSHttpStatus)return_status);
							break;
						}
					case Rule_dir_add:
						{
							char *info = NULL;
							int len = 0;
							int L = 0;
							get_url_param(url_cmd, url_cmd_length, "?", &info, &len);
							if(len <= 7 || strncmp(info, "http://", 7) != 0 || *(info+7) == '/') {
								ERROR_LOG("error data");
								goto rule_add_done;
							}

							if(info) {
								if(*(info + len - 1) != '/')
									L = 1;						
								int64_t  start_time = time(NULL);
								char *slice_dir  = (char *)malloc(len + 1 + L);
								if(slice_dir) {
									memset(slice_dir, 0, len + 1 + L);
									memcpy(slice_dir, info, len);

									if(L)
										memcpy(slice_dir + len, "/", L);
									pthread_rwlock_wrlock(&rwlock);
									char mes[URL_LEN + 128] = {0};
									snprintf(mes, sizeof(mes) - 1, "%s\t%ld\n",slice_dir, start_time);

									if(rule_fp) {
										TSfwrite(rule_fp, mes, strlen(mes));
										TSfflush(rule_fp); 
									}
									int ret = (unsigned int)trie_visit(pool.trie, slice_dir, visitor_print, (void *)time(0)) ;
									if (ret != 0) {
										if (intern(&pool, slice_dir,time(0)) == NULL) {
											ERROR_LOG("error: could not insert:%s",slice_dir);
										}
										ret = 1 ;
									}
									if(ret != 1) {
										if (intern(&pool, slice_dir,time(0)) == NULL) {
											ERROR_LOG("error: could not insert:%s",slice_dir);
										}
									}
									pthread_rwlock_unlock(&rwlock);
									free(slice_dir);
								}

								return_status = SUCCESS_STATUS_CODE;

								TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);
							}
rule_add_done:
							reenable = TS_EVENT_HTTP_ERROR;
							TSHttpTxnSetHttpRetStatus(txnp, (TSHttpStatus)return_status);
							break;
						}
					case Rule_dir_cancel:
						{
							char *info = NULL;
							int len = 0;
							int L = 0;
							get_url_param(url_cmd, url_cmd_length, "?", &info, &len);
							if(len <= 7 || strncmp(info, "http://", 7) != 0 || *(info+7) == '/') {
								char *str = (char *)malloc(url_cmd_length + 1);
								memset(str, 0, url_cmd_length + 1);
								memcpy(str, url_cmd, url_cmd_length);
								ERROR_LOG("error rule url_cmd %s\n", str);
								free(str);
							}else{
								if(info) {
									if(*(info + len - 1) != '/')
										L = 1;						
									char *slice_dir  = (char *)malloc(len + 1 + L);
									if(slice_dir) {
										memset(slice_dir, 0, len + 1 + L);
										memcpy(slice_dir, info, len);

										if(L)
											memcpy(slice_dir + len, "/", L);
										pthread_rwlock_wrlock(&rwlock);
										char mes[URL_LEN + 128] = {0};
										snprintf(mes, sizeof(mes) - 1, "%s\t0\n",slice_dir);

										if(rule_fp) {
											TSfwrite(rule_fp, mes, strlen(mes));
											TSfflush(rule_fp); 
										}
										trie_visit(pool.trie, slice_dir, visitor_print, (void *)1) ;
										pthread_rwlock_unlock(&rwlock);
										free(slice_dir);
									}
								}
							}

							return_status = SUCCESS_STATUS_CODE;;
							TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);
							reenable = TS_EVENT_HTTP_ERROR;
							TSHttpTxnSetHttpRetStatus(txnp, (TSHttpStatus)return_status);
							break;
						}
					case Rule_dir_none:
						break;
					default:
						break;
				}
				if(url_cmd) {
					TSfree(url_cmd);
				}
				break;
			} 

		case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE:
			if (TSHttpTxnCacheLookupStatusGet(txnp, &status) == TS_SUCCESS) {
				if (status == TS_CACHE_LOOKUP_HIT_FRESH) {
					char *url;
					char *str;
					int url_length;
					get_restore_url(txnp, &url, &url_length);
					if(url) {
						str = TSstrndup(url, url_length);
						str[url_length] = '\0';
					}else{
						break; 
					}
					unsigned int ret = 0;
					int num = 0 ;
					while(1) {
						char s_url[1024] = {0};
						split_str(str,s_url,'/');
						if(strlen(s_url) >= 7) {
							if(strcmp(s_url,"http://") == 0)
								break;

							memset(str,0,url_length);
							memcpy(str,s_url,strlen(s_url)-1);
							ret = (unsigned int)intern_soft_sec(&pool, s_url) ;
							if(ret > 0)
								break;
						}else{
							break;
						}
						if(num >10)
							break;
						num++;
					}

					if( ret > 0) {
						date = get_date_from_cached_hdr(txnp);
						now  = time(NULL);
						if( (now - DEFAULT_REVALIDATE_TIME) > ret ) {
							//need do sth.
						}else{
							if(date < ret){
								TSHttpTxnCacheLookupStatusSet(txnp, TS_CACHE_LOOKUP_HIT_STALE);	
							}
						}
					}

					if(url)
						TSfree(url);
					if(str)
						TSfree(str);
				}
			}
			break;
		case TS_EVENT_HTTP_SEND_RESPONSE_HDR:
			{
				TSMBuffer bufp;
				TSMLoc hdr_loc = NULL;

				if(TSHttpTxnClientRespGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
					if(hdr_loc) {
						TSHandleMLocRelease (bufp, TS_NULL_MLOC, hdr_loc);
					}
					TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
					break;
				}

				TSHttpStatus s = TSHttpHdrStatusGet(bufp, hdr_loc);
				if(s == (TSHttpStatus)SUCCESS_STATUS_CODE) {
					TSHttpHdrReasonSet(bufp, hdr_loc, "Success", 7);
				}else if(s == (TSHttpStatus)SUCCESS_INFO_STATUS_CODE) {
					TSHttpHdrReasonSet(bufp, hdr_loc, "Success", 7);

					pthread_rwlock_wrlock(&rwlock);
					char count_str[64] = {0};
					char mem_count_str[64] = {0}; 

					snprintf(count_str,sizeof(count_str)-1,"%ld",intern_count(&pool));			
					snprintf(mem_count_str,sizeof(mem_count_str)-1,"%0.3f MB",trie_size(pool.trie) / 1024.0 / 1024.0);
					pthread_rwlock_unlock(&rwlock);

					set_header(bufp, hdr_loc, "Rule-Dir-Count", 14,count_str,strlen(count_str));
					set_header(bufp, hdr_loc, "Rule-Dir-Mem", 12,mem_count_str,strlen(mem_count_str));
				}

				if(hdr_loc) {
					TSHandleMLocRelease (bufp, TS_NULL_MLOC, hdr_loc);
				}
				break;
			}
		default:
			break;
	}

	TSHttpTxnReenable(txnp, reenable);
	return 0;
}


int create_rule_dir()
{
	DIR *dir_fp = NULL;
	char rule_dir_path[1024] = {0};

	snprintf(rule_dir_path, sizeof(rule_dir_path) - 1, "%s%s", TSInstallDirGet(), RULE_DIR_PATH);
	
	if((dir_fp = opendir(rule_dir_path)) == NULL) {
		  if(mkdir(rule_dir_path, 0755) == -1) {
                           ERROR_LOG("create directory fail. Directory is %s\n", rule_dir_path);
			   return -1;
		  }
	} else {
		 closedir(dir_fp);
  }
	
	return 0;
}


int init_rule_log()
{
  TSFile rule_fp_init = NULL;
  char path[1024] = {0};
  snprintf(path, sizeof(path) - 1, "%s%s/%s", TSInstallDirGet(), RULE_DIR_PATH, RULE_FILE_NAME);

  rule_fp_init = TSfopen(path, "a");
  if(rule_fp_init) {
    TSfclose(rule_fp_init);
    rule_fp_init = NULL;
  }else{
    ERROR_LOG("open file:%s fail.",path);
  }

  return 1;
}


void reset_dir_url()
{
  char path[256] = {0};
  snprintf(path, sizeof(path) - 1, "%s%s/%s", TSInstallDirGet(), RULE_DIR_PATH, RULE_FILE_NAME);

  pthread_rwlock_rdlock(&rwlock);
     unlink(path);

     reset_fp_init = TSfopen(path, "a");
     if(reset_fp_init) {
        trie_visit(pool.trie, "", visitor_flush, NULL) ;
        TSfflush(reset_fp_init); 
        TSfclose(reset_fp_init);
     }else{
        ERROR_LOG("open file:%s fail.",path);
     }

    rule_fp = TSfopen(path, "a");

  pthread_rwlock_unlock(&rwlock);

  return;
}


int load_validable_rule_url()
{
	char path[1024] = {0};
	snprintf(path, sizeof(path) - 1, "%s%s/%s", TSInstallDirGet(), RULE_DIR_PATH, RULE_FILE_NAME);

	TSFile fh = TSfopen(path, "r");
	if(!fh) {
		ERROR_LOG("can't open file:%s ",path);
		return 0;
	}

	char buf[URL_LEN + 10] = {0};
	while(TSfgets(fh, buf ,sizeof(buf) - 1) != NULL) {
		if(strncmp(buf, "http://", 7) != 0) {
			ERROR_LOG("has error data no http  . %s",buf);
			memset(buf, 0, sizeof(buf));
			continue;
		}
		*(buf + strlen(buf) - 1) = '\0';
		char *q = strstr(buf + 7, "\t");
		if(!q /*|| strlen(q+1) < 10 */) {
			ERROR_LOG("has error data. %s", buf);
			memset(buf, 0, sizeof(buf));
			continue;
		}
		q++;
		*(q - 1)= '\0';
		int len = strlen(buf);	
		char *stale_url = (char *)malloc(len + 1);
		memset(stale_url, 0, len + 1);
		memcpy(stale_url, buf, len);
		int64_t start_time = 0 ;
		start_time = (time_t)atoi(q);

		if( ((time(0) - start_time) < DEFAULT_REVALIDATE_TIME) || (start_time == 0) ) {
			pthread_rwlock_wrlock(&rwlock);
			if(start_time == 0)
				start_time = 1 ; 
			int ret = (unsigned int)trie_visit(pool.trie, stale_url, visitor_print, (void *)start_time) ;
			if(start_time == 1)
				start_time = 0;
			if (ret != 0) {
				if (intern(&pool, stale_url,start_time) == NULL) {
					ERROR_LOG("error:init  could not insert:%s",stale_url);
				}
				ret = 1 ;
			}
			if(ret != 1) {
				if (intern(&pool, stale_url,start_time) == NULL) {
					ERROR_LOG("error:init  could not insert:%s",stale_url);
				}
			}
			pthread_rwlock_unlock(&rwlock);
		}
		if(stale_url)
			free(stale_url);
		memset(buf, 0, sizeof(buf));
	}

	TSfclose(fh);
	reset_dir_url();	

	return 1;
}

void
TSPluginInit(int argc, const char *argv[])
{
	TSPluginRegistrationInfo info;
	TSCont main_cont ;

	info.plugin_name   = PLUGIN_NAME;
	info.vendor_name   = "Apache Software Foundation";
	info.support_email = "dev@trafficserver.apache.org";

	if (TSPluginRegister(1.0,&info) != TS_SUCCESS) {
		ERROR_LOG("Plugin registration failed.");
		return;
	}

        if(create_rule_dir() <  0) {
           ERROR_LOG("create_rule_dir failure");
           return ;
        }

	init_rule_log();

	if (intern_init(&pool) != 0) {
		ERROR_LOG("error: intern pool failure");
		return ;
	}

	load_validable_rule_url();

	main_cont = TSContCreate(rule_handler, NULL);
	TSHttpHookAdd(TS_HTTP_POST_REMAP_HOOK,main_cont);
	TSHttpHookAdd(TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, main_cont);
}
