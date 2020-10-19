#ifndef __QAT_HASH_H__
#define __QAT_HASH_H__

//external functions
int init_qat();
int get_engine_num();
int get_max_object_size();
int get_cont_piece_size();
int get_engine();
void* get_engine_buffs(int eng_i);
int get_eng_current_len(int eng_i);
void reset_engine(int eng_i);
void release_engine(int eng_i);
int md5_write(int eng_i, const unsigned char* buff, int len, int cp_mem);
int md5_sum(int eng_i, unsigned char *digest);
int cleanup_qat();

//internal functions
int release_engines();

int helloworld();

#endif