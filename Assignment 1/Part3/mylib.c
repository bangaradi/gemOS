#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#define FOUR_MB  ( 4*1024*1024 )

int flag = 0;
void* freelist = NULL;

void* allocate_new_mem(void* prev, void* next, size_t multiple, int flag){
	size_t size_to_alloc;
	if(flag == 0) size_to_alloc = multiple * FOUR_MB + 8;
	else size_to_alloc = multiple*FOUR_MB;
	void* mem = mmap(NULL, size_to_alloc, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	*(unsigned long*) mem = size_to_alloc;
	void** addr = mem;
	addr[1] = next;
	addr[2] = prev;
	return mem;
}

void* allocate_mem(void* head, void* prev_head, unsigned long size){
	if(head == NULL){
		size_t mult = (size%FOUR_MB == 0) ? size/FOUR_MB : size/FOUR_MB + 1;
		void* mem = allocate_new_mem(prev_head, NULL, mult, size%FOUR_MB);
		if(prev_head == NULL) freelist = mem;
		else *(void**)(prev_head+8) = mem;
		return allocate_mem(mem, prev_head, size);
	}

	unsigned long enough_size = (size + 8 < 24) ? 24 : (size+8);
	unsigned long pad = (enough_size%8 == 0) ? 0 : ((enough_size/8 + 1)*8 - enough_size);
	unsigned long available_size = *(unsigned long*)(head);
	void* next = *(void**)(head+8);
	void* prev = *(void**)(head + 16);


	if(available_size - size < 24 && available_size - size >=0){
		if(prev != NULL){
			*(void**)(prev+8) = next;
			if(next != NULL) *(void**)(next + 16) = prev;
		}else{
			freelist = next;
			if(next != NULL) *(void**)(next + 16) = prev;
		}
		return head+8;
	}else if(available_size - size >= 24 && available_size - size >= 0){
		//break it up
		*(unsigned long*)(head) = enough_size + pad;
		if(prev != NULL){
			void* temp_head = head;
			temp_head = temp_head + enough_size + pad;
			*(unsigned long*)(temp_head) = available_size - (enough_size + pad);
			*(void**)(temp_head+8) = next;
			*(void**)(temp_head + 16) = prev;
		}else{
			void* temp_head = head;
			temp_head = temp_head + enough_size + pad;
			*(unsigned long*)(temp_head) = available_size - (enough_size + pad);
			*(void**)(temp_head+8) = next;
			*(void**)(temp_head + 16) = prev;
			freelist = temp_head;	
		}
		return head+8;
	}else{
		return allocate_mem(next, head, size);
	}
}

void *memalloc(unsigned long size) 
{
	if(flag == 0){
		flag = 1;
		return allocate_mem(NULL, NULL, size);
	}else{
		return allocate_mem(freelist, NULL, size);
	}
	
	return NULL;
}

int memfree(void *ptr)
{
	ptr = ptr-8;
	unsigned long size_at_back = 0, size_at_front = 0;
	void* itr = freelist;
	while(itr != NULL){
		unsigned long block_size = *(unsigned long*)(itr);
		if(itr + block_size == ptr){
			size_at_back = block_size;
			break;
		}else{
			itr = *(void**)(itr+8);
		}
	}
	unsigned long size_of_block = *(unsigned long*)(ptr);
	itr = freelist;
	int flg = 0;
	while(itr != NULL){
		unsigned long block_size = *(unsigned long*) (itr);
		if(itr - size_of_block == ptr){
			size_at_front = block_size;
			break;
		}else{
			itr = *(void**)(itr+8);
		}
	}
	if(size_at_back == 0 && size_at_front == 0){
		*(void**)(ptr+8) = freelist;
		*(void**)(ptr + 16) = NULL;
		if(freelist != NULL) *(void**)(freelist + 16) = ptr;
		freelist = ptr;
	}else if(size_at_back == 0 && size_at_front != 0){
		*(unsigned long*)(ptr) = size_at_front + size_of_block;
		void* next_of_next = *(void**)(ptr + size_of_block + 8);
		if(freelist - ptr >= 0 && freelist - ptr <= size_of_block) *(void**)(ptr+8) = NULL;
		else *(void**)(ptr+8) = freelist;
		*(void**)(ptr + 16) = NULL;
		*(void**)(freelist+8) = next_of_next;
		*(void**)(freelist + 16) = ptr;
		freelist = ptr;
	}else if(size_at_back != 0 && size_at_front == 0){
		void* back = ptr - size_at_back;
		*(unsigned long*)(back) = size_at_back + size_of_block;
		void* next = *(void**)(back+8);
		if(ptr - freelist >= 0 && ptr - freelist <= size_at_back) *(void**)(back+8) = NULL;
		else *(void**)(back+8) = freelist;
		*(void**)(back + 16) = NULL;
		*(void**)(freelist+8) = next;
		*(void**)(freelist + 16) = back;
		freelist = back;
	}else{
		void* front = ptr + size_of_block;
		void* back = ptr - size_at_back;
		*(unsigned long*)(back) = size_at_back + size_of_block + size_at_front;
		void* next = *(void**)(front+8);
		if(freelist - back > 0 && freelist - back <= (size_at_back + size_of_block)) *(void**)(back+8) = *(void**)(back+8);
		else *(void**)(back+8) = next;
		*(void**)(back + 16) = NULL;
		*(void**)(freelist+8) = next;
		*(void**)(freelist + 16) = back;
		freelist = back;
	}


	return 0;
}	
