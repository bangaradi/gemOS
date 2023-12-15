#include<context.h>
#include<memory.h>
#include<lib.h>
#include<entry.h>
#include<file.h>
#include<tracer.h>

///////////////////////////////////////////////////////////////////////////
//// 		Start of Trace buffer functionality 		              /////
///////////////////////////////////////////////////////////////////////////
void print_unsigned_long(unsigned long value) {
    char buffer[21]; // Enough to hold all digits of an unsigned long in base 10
    int i = sizeof(buffer) - 1;

    buffer[i] = '\0'; // Null-terminate the string
    if (value == 0) {
        buffer[--i] = '0';
    } else {
        while (value > 0) {
            buffer[--i] = '0' + (value % 10); // Convert the least significant digit to a character
            value /= 10; // Remove the least significant digit
        }
    }

    printk("%s", &buffer[i]);
}
int is_valid_mem_range(unsigned long buff, u32 count, int access_bit) 
{
	// printk("is valid mem range called----\n");
	// printk("count: %d\n", count);
	struct exec_context* ctx = get_current_ctx();
	// printk("to check for ::::: "); print_unsigned_long(buff);printk("  to  ");print_unsigned_long(buff + count);printk("\n");
	// printk("the valid SEG_MM ranges are: \n");

	int max_mem_segments = sizeof(ctx->mms)/sizeof(struct mm_segment);
	int flag = 0;
	for(int i=0; i<max_mem_segments; i++){
		// print_unsigned_long(ctx->mms[i].start);printk(" :: ");print_unsigned_long(ctx->mms[i].end);printk("  access_flags: %d\n", ctx->mms[i].access_flags);
		if(i!=MM_SEG_STACK && buff >= ctx->mms[i].start && (buff + count) <= ctx->mms[i].end-1){
			flag = 1;
			// printk("flag became 1, val in mem_seg\n");
			if(!(ctx->mms[i].access_flags & access_bit)){
				flag = 0;
				// printk("access bit issue.\n");
				// return -EBADMEM;
			}
		}
		if(i==MM_SEG_STACK && buff <= ctx->mms[i].end && (buff - count) >= ctx->mms[i].start-1){
			flag = 1;
			// printk("flag became 1, val in mem_seg\n");
			if(!(ctx->mms[i].access_flags & access_bit)){
				flag = 0;
				// printk("access bit issue.\n");
				// return -EBADMEM;
			}
		}
	}

	// printk("vm area checking.... \n");
	struct vm_area* vm = ctx->vm_area;
	// if(vm == NULL) printk("VM IS NULL\n");
	while(vm != NULL){
		// print_unsigned_long(vm->vm_start);printk(" :: ");print_unsigned_long(vm->vm_end);printk("  access_flags: %d\n", vm->access_flags);
		if(buff >= vm->vm_start && (buff + count) <= vm->vm_end-1){
			flag = 1;
			// printk("flag became 1, val in vm_area\n");
			if(!(vm->access_flags & access_bit)){
				// printk("issue with access bit.\n");
				flag = 0;
				// return -EBADMEM;
			}
		}
		vm = vm->vm_next;
	}

	if(flag == 0) {
		// printk("flag is still zero.\n");
		return -EBADMEM;
	}
	return 0;
}



long trace_buffer_close(struct file *filep)
{
	// printk("inside trace buffer close\n");
	// free trace_buffer memory
	os_page_free(USER_REG,filep->trace_buffer->mem);
	// free trace_buffer_info
	os_free(filep->trace_buffer, sizeof(struct trace_buffer_info));
	// free fops
	os_free(filep->fops, sizeof(struct fileops));
	// free file
	// printk("before filep is free: \n");
	// if(filep != NULL) printk("filep is NOT NULL\n");
	os_free(filep, sizeof(struct file));
	filep = NULL;
	// printk("freed\n");
	// if(filep == NULL) printk("filep is NULL\n");
	// struct exec_context* ctx = get_current_ctx();
	// int free_fd = -EINVAL;
	// for(int i=0; i<MAX_OPEN_FILES; i++){
	// 	if(ctx->files[i] == NULL){
	// 		free_fd = i;
	// 		break;
	// 	}
	// }
	// printk("free at: %d \n", free_fd);
	return 0;	
}

int trace_buffer_read_util(struct file *filep, char *buff, u32 count)
{
	// printk("checking for validity:\n");
	// printk("inside trace buffer read\n");
	//check if trace buffer is readable
	// if(!(filep->mode & 1)) return -EINVAL;
	int ret = 0;
	for(int i=0; i<count; i++){
		if(filep->trace_buffer->alloted_bytes == 0){
			break;
		}
		buff[i] = filep->trace_buffer->mem[filep->trace_buffer->read_offset];
		filep->trace_buffer->read_offset += 1;
		filep->trace_buffer->read_offset %= TRACE_BUFFER_MAX_SIZE;
		filep->trace_buffer->alloted_bytes -= 1;
		ret += 1;
	}
	// printk("read_offset: %d, write_offset: %d, alloted_bytes: %d\n", filep->trace_buffer->read_offset, filep->trace_buffer->write_offset, filep->trace_buffer->alloted_bytes);
	return ret;
}


int trace_buffer_read(struct file *filep, char *buff, u32 count)
{
	// printk("checking for validity:\n");
	if(buff == NULL) return -EBADMEM;
	int val = is_valid_mem_range((unsigned long)buff, count, O_WRITE);
	if(val == -EBADMEM){
		// printk("val is EBADMEM\n");
		return -EBADMEM;
	};
	// printk("inside trace buffer read\n");
	//check if trace buffer is readable
	// if(!(filep->mode & 1)) return -EINVAL;
	int ret = 0;
	for(int i=0; i<count; i++){
		if(filep->trace_buffer->alloted_bytes == 0){
			break;
		}
		buff[i] = filep->trace_buffer->mem[filep->trace_buffer->read_offset];
		filep->trace_buffer->read_offset += 1;
		filep->trace_buffer->read_offset %= TRACE_BUFFER_MAX_SIZE;
		filep->trace_buffer->alloted_bytes -= 1;
		ret += 1;
	}
	// printk("read_offset: %d, write_offset: %d, alloted_bytes: %d\n", filep->trace_buffer->read_offset, filep->trace_buffer->write_offset, filep->trace_buffer->alloted_bytes);
	return ret;
}

int trace_buffer_write_util(struct file *filep, char *buff, u32 count)
{
	// printk("checking for validity:\n");
	// printk("count: %d\n", count);
	// printk("inside trace buffer write\n");
	//check if trace buffer is writable
	// if(!(filep->mode & 2)) return -EINVAL;
	int ret = 0;
	for(int i=0; i<count; i++){
		if(filep->trace_buffer->alloted_bytes == TRACE_BUFFER_MAX_SIZE){
			break;
		}
		char t = buff[i];
		filep->trace_buffer->mem[filep->trace_buffer->write_offset] = t;
		filep->trace_buffer->write_offset += 1;
		// printk("write_offset: ")
		filep->trace_buffer->write_offset %= TRACE_BUFFER_MAX_SIZE;
		filep->trace_buffer->alloted_bytes += 1;
		ret += 1;
	}
	// printk("read_offset: %d, write_offset: %d, alloted_bytes: %d\n", filep->trace_buffer->read_offset, filep->trace_buffer->write_offset, filep->trace_buffer->alloted_bytes);
    return ret;
}

int trace_buffer_write(struct file *filep, char *buff, u32 count)
{
	// printk("checking for validity:\n");
	// printk("count: %d\n", count);
	if(buff == NULL) return -EBADMEM;
	int val = is_valid_mem_range((unsigned long)buff, count, O_READ);
	if(val == -EBADMEM){
		return -EBADMEM;
	};

	// if(!(filep->mode & 2)) return -EINVAL;
	// printk("inside trace buffer write\n");
	//check if trace buffer is writable
	int ret = 0;
	for(int i=0; i<count; i++){
		if(filep->trace_buffer->alloted_bytes == TRACE_BUFFER_MAX_SIZE){
			break;
		}
		char t = buff[i];
		filep->trace_buffer->mem[filep->trace_buffer->write_offset] = t;
		filep->trace_buffer->write_offset += 1;
		// printk("write_offset: ")
		filep->trace_buffer->write_offset %= TRACE_BUFFER_MAX_SIZE;
		filep->trace_buffer->alloted_bytes += 1;
		ret += 1;
	}
	// printk("read_offset: %d, write_offset: %d, alloted_bytes: %d\n", filep->trace_buffer->read_offset, filep->trace_buffer->write_offset, filep->trace_buffer->alloted_bytes);
    return ret;
}

int sys_create_trace_buffer(struct exec_context *current, int mode)
{
	int free_fd = -EINVAL;
	for(int i=0; i<MAX_OPEN_FILES; i++){
		if(current->files[i] == NULL){
			free_fd = i;
			break;
		}
	}
	if(free_fd != -EINVAL){
		// initialize the fields of the file object
		// struct file new_file_ob;
		struct file* new_file_ob = (struct file*)os_alloc(sizeof(struct file));
		if(!new_file_ob){
			printk("error while allocating new_file_ob\n");
			return -ENOMEM;
		}
		new_file_ob->type = TRACE_BUFFER;
		if(mode == O_READ || mode == O_WRITE || mode == O_RDWR || mode == O_EXEC || mode == O_CREAT) new_file_ob->mode = mode;
		else return -EINVAL;
		new_file_ob->offp = 0;
		new_file_ob->ref_count = 1;
		new_file_ob->inode = NULL;
		new_file_ob->trace_buffer = NULL;
		new_file_ob->fops = NULL;

		// allocate trace_buffer_info
		// struct trace_buffer_info new_trace_buffer;
		struct trace_buffer_info* new_trace_buffer = (struct trace_buffer_info*)os_alloc(sizeof(struct trace_buffer_info));
		if(!new_trace_buffer){
			return -ENOMEM;
		}
		new_trace_buffer->read_offset = 0;
		new_trace_buffer->write_offset = 0;
		new_trace_buffer->alloted_bytes = 0;
		new_trace_buffer->mem = (char*)os_page_alloc(USER_REG);
		
		new_file_ob->trace_buffer = new_trace_buffer;

		// allocate the fileops, and pointers to the read, write and close
		// struct fileops new_fops;
		struct fileops* new_fops = (struct fileops*)os_alloc(sizeof(struct fileops));
		if(!new_fops){
			printk("error while allocating new_fops \n");
			return -ENOMEM;
		}
		new_fops->read = trace_buffer_read;
		new_fops->write = trace_buffer_write;
		new_fops->lseek = NULL;
		new_fops->close = trace_buffer_close;

		new_file_ob->fops = new_fops;

		// assign the file object to the context
		current->files[free_fd] = new_file_ob;
	}
	return free_fd;
}

///////////////////////////////////////////////////////////////////////////
//// 		Start of strace functionality 		      	              /////
///////////////////////////////////////////////////////////////////////////

int get_num_params(int syscall_num){
		// printk("inside num params: %d\n", syscall_num);
	    switch(syscall_num) {
        case SYSCALL_EXIT: return 1+1; // exit(int)
        case SYSCALL_GETPID: return 0+1; // getpid()
		// case SYSCALL_GETPPID:
        case SYSCALL_FORK: return 0+1; // fork() 
        case SYSCALL_CFORK: return 0+1; // cfork()
        case SYSCALL_VFORK: return 0+1; // vfork()
        case SYSCALL_GET_USER_P: return 0+1; // get_user_page_stats()
        case SYSCALL_GET_COW_F: return 0+1; // get_cow_fault_stats()
        case SYSCALL_SIGNAL: return 2+1; // signal(int, void*)
        case SYSCALL_SLEEP: return 1+1; // sleep(int)
        case SYSCALL_EXPAND: return 2+1; // expand(unsigned, int)
        case SYSCALL_CLONE: return 2+1; // clone(void*, long)
        case SYSCALL_DUMP_PTT: return 1+1; // dump_page_table(char*)
        case SYSCALL_PHYS_INFO: return 0+1; // physinfo()
        case SYSCALL_STATS: return 0+1; // get_stats()
        case SYSCALL_CONFIGURE: return 1+1; // configure(struct os_configs*)
        case SYSCALL_MMAP: return 4+1; // mmap(void*, int, int, int)
        case SYSCALL_MUNMAP: return 2+1; // munmap(void*, int)
        case SYSCALL_MPROTECT: return 3+1; // mprotect(void*, int, int)
        case SYSCALL_PMAP: return 1+1; // pmap(int)
        case SYSCALL_OPEN: return 2+1; // open(char*, int, ...)
        case SYSCALL_WRITE: return 3+1; // write(int, void*, int)
        case SYSCALL_READ: return 3+1; // read(int, void*, int)
        case SYSCALL_DUP: return 1+1; // dup(int)
        case SYSCALL_DUP2: return 2+1; // dup2(int, int)
        case SYSCALL_CLOSE: return 1+1; // close(int)
        case SYSCALL_LSEEK: return 3+1; // lseek(int, long, int)
        case SYSCALL_FTRACE: return 4+1; // ftrace(unsigned long, long, long, int)
		case SYSCALL_TRACE_BUFFER: return 1+1;
        case SYSCALL_START_STRACE: return 2+1; // start_strace(int, int)
        case SYSCALL_END_STRACE: return 0+1; // end_strace()
        case SYSCALL_STRACE: return 2+1; // strace(int, int)
        case SYSCALL_READ_STRACE: return 3+1; // read_strace(int, void*, int)
        case SYSCALL_READ_FTRACE: return 3+1; // read_ftrace(int, void*, int)
        default: return -1; // Unknown syscall number
    }
	// return 5; //hardcoded for now...
}

int perform_tracing(u64 syscall_num, u64 param1, u64 param2, u64 param3, u64 param4)
{
	// printk("syscall num: %d, param1: %d, param2: %d, param3: %d, param4: %d \n", syscall_num, param1, param2, param3, param4);
	// printk("syscall num: ");print_unsigned_long(syscall_num);printk(" param1: ");print_unsigned_long(param1);printk(" param2: ");print_unsigned_long(param2);printk(" param3: ");print_unsigned_long(param3);printk(" param4: ");print_unsigned_long(param4); printk("\n");
	struct exec_context* ctx = get_current_ctx();
	// printk("strace_fd is: %d \n", ctx->st_md_base->strace_fd);
	if(syscall_num == SYSCALL_END_STRACE) return 0;
	if(!ctx->st_md_base->is_traced) return 0;
	// printk("here ...\n");
	if(ctx->st_md_base->tracing_mode == FULL_TRACING){
		u64 arr[5] = {syscall_num, param1, param2, param3, param4};
		//update the count
		ctx->st_md_base->count += 1;
		//go to the last free block of strace_info
			//update it's next, and syscall number
		// struct strace_info* new_strace_info = os_alloc(sizeof(struct strace_info));
		// new_strace_info->syscall_num = syscall_num;
		// new_strace_info->next = NULL;
		// ctx->st_md_base->last = new_strace_info;
		//add the syscall_num, param1, param2, param4, param4 into the trace_buffer.
		struct file* trace_buff_file = ctx->files[ctx->st_md_base->strace_fd];

		int num_params = get_num_params(syscall_num);
		// printk("num_params: %d\n", num_params);
		for(int i=0; i<num_params; i++){
			u64* temp_buff = os_alloc(sizeof(u64));
			*temp_buff = arr[i];
			int dumper = trace_buffer_write_util(trace_buff_file, (char*)temp_buff, 8);
			// printk("value of dumper: %d \n", dumper);
			char* tb = trace_buff_file->trace_buffer->mem;
			// printk("checking if written succesfully: trace_buff_file[0] : %d \n", ((u64*)tb)[i]);
			os_free(temp_buff, sizeof(u64));
		}
		// u64* temp_buff = os_alloc(sizeof(u64));
		// trace_buffer_write(trace_buff_file, (char*)temp_buff, 8);
		// os_free(temp_buff, sizeof(u64));

		return 0;
	}else{
		// printk("inside filtered tracing mode\n");
		ctx = get_current_ctx();
		// printk("the ctx is : "); print_unsigned_long((u64)ctx);printk("\n");
		struct strace_info* iterator = ctx->st_md_base->next;
		while(1){
			// printk("the iter->syscall_num: %d, syscall_num: %d\n", iterator->syscall_num, syscall_num);
			if(iterator == NULL){
				// printk("iter has become NULL\n");
				break;
			}
			if(iterator->syscall_num == syscall_num){
			// printk("syscall num: %d, param1: %d, param2: %d, param3: %d, param4: %d \n", syscall_num, param1, param2, param3, param4);
			// printk("syscall num: ");print_unsigned_long(syscall_num);printk(" param1: ");print_unsigned_long(param1);printk(" param2: ");print_unsigned_long(param2);printk(" param3: ");print_unsigned_long(param3);printk(" param4: ");print_unsigned_long(param4); printk("\n");
				u64 arr[5] = {syscall_num, param1, param2, param3, param4};
				//update the count
				ctx->st_md_base->count += 1;
				//go to the last free block of strace_info
					//update it's next, and syscall number
				// struct strace_info* new_strace_info = os_alloc(sizeof(struct strace_info));
				// new_strace_info->syscall_num = syscall_num;
				// new_strace_info->next = NULL;
				// ctx->st_md_base->last = new_strace_info;
				//add the syscall_num, param1, param2, param4, param4 into the trace_buffer.
				struct file* trace_buff_file = ctx->files[ctx->st_md_base->strace_fd];

				int num_params = get_num_params(syscall_num);
				// printk("num_params: %d\n", num_params);
				for(int i=0; i<num_params; i++){
					u64* temp_buff = os_alloc(sizeof(u64));
					*temp_buff = arr[i];
					int dumper = trace_buffer_write_util(trace_buff_file, (char*)temp_buff, 8);
					// printk("value of dumper: %d \n", dumper);
					char* tb = trace_buff_file->trace_buffer->mem;
					// printk("checking if written succesfully: trace_buff_file[0] : %d \n", ((u64*)tb)[i]);
					os_free(temp_buff, sizeof(u64));
				}
			}
			iterator = iterator->next;
		}
	}
	return 0;
}

int check_valid_syscall_num(int syscall_num){
    switch (syscall_num) {
        case SYSCALL_EXIT:
        case SYSCALL_GETPID:
        case SYSCALL_EXPAND:
        case SYSCALL_SHRINK:
        case SYSCALL_ALARM:
        case SYSCALL_SLEEP:
        case SYSCALL_SIGNAL:
        case SYSCALL_CLONE:
        case SYSCALL_FORK:
        case SYSCALL_STATS:
        case SYSCALL_CONFIGURE:
        case SYSCALL_PHYS_INFO:
        case SYSCALL_DUMP_PTT:
        case SYSCALL_CFORK:
        case SYSCALL_MMAP:
        case SYSCALL_MUNMAP:
        case SYSCALL_MPROTECT:
        case SYSCALL_PMAP:
        case SYSCALL_VFORK:
        case SYSCALL_GET_USER_P:
        case SYSCALL_GET_COW_F:
        case SYSCALL_OPEN:
        case SYSCALL_READ:
        case SYSCALL_WRITE:
        case SYSCALL_DUP:
        case SYSCALL_DUP2:
        case SYSCALL_CLOSE:
        case SYSCALL_LSEEK:
        case SYSCALL_FTRACE:
        case SYSCALL_TRACE_BUFFER:
        case SYSCALL_START_STRACE:
        case SYSCALL_END_STRACE:
        case SYSCALL_READ_STRACE:
        case SYSCALL_STRACE:
        case SYSCALL_READ_FTRACE:
        case SYSCALL_GETPPID:
            return 1;
        default:
            return 0;
    }
}

int sys_strace(struct exec_context *current, int syscall_num, int action)
{
	// printk("sys_strace called\n");
	// printk("the ctx is : "); print_unsigned_long((u64)current);printk("\n");
	if(!check_valid_syscall_num(syscall_num)) return -EINVAL;
	struct strace_head* strace_head = current->st_md_base;
	if(action == ADD_STRACE){
		if(current->st_md_base == NULL){
			// printk("the st_md_base is NULL: \n");
			current->st_md_base = (struct strace_head*)os_alloc(sizeof(struct strace_head));
			struct strace_info* strace_info = (struct strace_info*)os_alloc(sizeof(struct strace_info));
			strace_info->next = NULL;
			strace_info->syscall_num = syscall_num;
			current->st_md_base->next = strace_info;
			current->st_md_base->last = strace_info;

		}else{
			struct strace_info* iter = current->st_md_base->next;
			while(1){
				if(iter == NULL){
					// printk("first element only NULL;\n");
					break;
				}
				if(iter->syscall_num == syscall_num) {
					// printk("already exists \n");
					return 0; // already exists
					// break;
				}
				if(iter->next == NULL){
					// printk("NULL afterwards\n");
					break;
				}
				iter = iter->next;
				// if(iter == NULL){
				// 	printk("the iter has become NULL [INSIDE ADD STRACE]\n");
				// 	break;
				// } 
			}

			struct strace_info* strace_info = (struct strace_info*)os_alloc(sizeof(struct strace_info));
			strace_info->syscall_num = syscall_num;
			strace_info->next = NULL;
			if(iter != NULL) iter->next = strace_info;
			else{
				current->st_md_base->next = strace_info;
			}
			current->st_md_base->last = strace_info;
		}
		// return 0;
	}else if(action == REMOVE_STRACE){
		// printk("remove strace called \n");
		struct strace_info* iter = current->st_md_base->next;
		struct strace_info* prev = NULL;
		while(1){
			if(iter->syscall_num == syscall_num) break;
			if(iter->next == NULL){
				return -EINVAL;
				break;
			}
			prev = iter;
			iter = iter->next;
		}

		if(prev != NULL) prev->next = iter->next;
		else if(prev == NULL) current->st_md_base->next = iter->next;
		os_free(iter, sizeof(struct strace_info));
		// if(current->st_md_base->next == NULL){
		// 	os_free(current->st_md_base)
		// }
	}

	//printing all the elements of the list: 
	// printk("printing all the elements of the syscall list: \n");
	// struct strace_info* iter = current->st_md_base->next;
	// while(1){
	// 	if(iter == NULL) break;
	// 	printk("syscall num : %d\n", iter->syscall_num);
	// 	iter = iter->next;
	// }
	return 0;
}

int sys_read_strace(struct file *filep, char *buff, u64 count)
{
	u64* trace_buff = (u64*)filep->trace_buffer->mem;
	u64* entry_buff = (u64*)buff;

	// for(int i=0; i<count*5; i++)
	// 	printk("trace_buff[%d] %d , entry_buff[%d] %d \n", i, trace_buff[i], i, entry_buff[i]);

	int offset = 0;
	int offseti=0;
	for(int i=0; i<count; i++){	
		// printk("offseti : %d \n", offseti);	
		int num_params = get_num_params((u32)trace_buff[offseti]);
		// printk("num_params inside sys_read_trace : %d \n", num_params);
		int adder = 0;
		for(int j=0; j<num_params; j++){
			adder += trace_buffer_read_util(filep, buff + offset + j*8, 8); //hardcoding to be changed here...
			if(adder == 0) break;
		}
		if(adder == 0) break;
		offset += adder;
		offseti += num_params;
	}
	// printk("offseti : %d  \n", offseti);
	// for(int i=0; i<offseti; i++)
	// 	printk("trace_buff[%d] %d , entry_buff[%d] %d \n", i, trace_buff[i], i, entry_buff[i]);
	return offset; //TODO
}

int sys_start_strace(struct exec_context *current, int fd, int tracing_mode)
{
	current->st_md_base->count = 0;
	current->st_md_base->is_traced = 1;
	current->st_md_base->strace_fd = fd;
	current->st_md_base->tracing_mode = tracing_mode;
	// current->st_md_base->next = NULL;
	// current->st_md_base->last = NULL;
	return 0;
}

int sys_end_strace(struct exec_context *current)
{
	current->st_md_base->count = 0;
	current->st_md_base->is_traced = 0;

	return 0;
}



///////////////////////////////////////////////////////////////////////////
//// 		Start of ftrace functionality 		      	              /////
///////////////////////////////////////////////////////////////////////////
unsigned long invalid_mem;
u8 backup[4];

long do_ftrace(struct exec_context *ctx, unsigned long faddr, long action, long nargs, int fd_trace_buffer)
{
	// printk("the function addr is: ");print_unsigned_long(faddr);printk("\n");
	// invalid_mem = faddr;
	// if(ctx->ft_md_base == NULL){
	// 	ctx->ft_md_base = os_alloc(sizeof(struct ftrace_head));
	// 	ctx->ft_md_base->count = 0;
	// 	ctx->ft_md_base->next = NULL;
	// 	ctx->ft_md_base->last = NULL;
	// }
	if(action == ADD_FTRACE){
		// printk("the number of arguments of function added: %d \n", nargs);
		if(ctx->ft_md_base->count == FTRACE_MAX) return -EINVAL;
		//find if already exists, if yes return -EINVAL
		struct ftrace_info* iter = ctx->ft_md_base->next;
		while(iter != NULL){
			if(iter->faddr == faddr) return -EINVAL;
			iter = iter->next;
		}
		//if it doesn't exist already update the count and update the *last, and the corresponding values
		struct ftrace_info* new = os_alloc(sizeof(struct ftrace_info));
		// ctx->ft_md_base->count += 1; // update the count
		new->faddr = faddr;
		new->num_args = nargs;
		new->fd = fd_trace_buffer;
		new->capture_backtrace = 0;
		new->next = NULL; // added the corresponding values
		if(ctx->ft_md_base->last != NULL) ctx->ft_md_base->last->next = new; //udpate the last
		ctx->ft_md_base->last = new; // update the last
		if(ctx->ft_md_base->next == NULL) ctx->ft_md_base->next = new;
	}
	if(action == ENABLE_FTRACE){
		//find the struct_info that is added corresponding to the given function addr
		struct ftrace_info* iter = ctx->ft_md_base->next;
		int flag = 0;
		while(1){
			if(iter == NULL) break;
			if(iter->faddr == faddr){
				flag = 1;
				break;
			}
			iter = iter->next;
		}
		if(flag == 0) return -EINVAL;
		//code for corrupting the first instruciton
		char* fad = (char*)iter->faddr;
		if(((u8*)fad)[0] == INV_OPCODE) return 0;
		for(int i=0; i<4; i++){
			iter->code_backup[i] = ((u8*)fad)[i];
			((u8*)fad)[i] = INV_OPCODE;
		}
	}
	if(action == DISABLE_FTRACE){
		// find the ftrace_info
		struct ftrace_info* iter = ctx->ft_md_base->next;
		int flag = 0;
		while(1){
			if(iter == NULL) break;
			if(iter->faddr == faddr){
				flag = 1;
				break;
			}
			iter = iter->next;
		}
		if(flag == 0) return -EINVAL;

		// check if ftrace is enabled, if yes, de-corrupt. if no, do nothing
		char* fad = (char*)(iter->faddr);
		if(((u8*)fad)[0] == INV_OPCODE){ // ftrace is enabled
			for(int i=0; i<4; i++){
				((u8*)fad)[i] = iter->code_backup[i]; //decorrupting
			}
		}

		return 0;
	}
	if(action == REMOVE_FTRACE){
		// find the ftrace_info
		// printk("inside REMOVE_FTRACE\n");
		struct ftrace_info* iter = ctx->ft_md_base->next;
		int flag = 0;
		while(1){
			if(iter == NULL) break;
			if(iter->faddr == faddr){
				// printk("found!\n");
				flag = 1;
				break;
			}
			iter = iter->next;
		}
		if(flag == 0) return -EINVAL;

		// check if the part is corrupt. if yes decorrupt and then remove. else remove directly from the list.
		char* fad = (char*)(iter->faddr);
		if(((u8*)fad)[0] == INV_OPCODE){ // corrupted
			for(int i=0; i<4; i++){
				((u8*)fad)[i] = iter->code_backup[i]; //decorrupting
			}
		}
		struct ftrace_info* prev = NULL;
		struct ftrace_info* to_remove = iter;
		iter = ctx->ft_md_base->next;
		while(iter!=NULL && iter!=to_remove){
			prev = iter;
			iter = iter->next;
		}
		if(iter == NULL) return -EINVAL;
		if(iter == ctx->ft_md_base->last){
			if(prev != NULL) ctx->ft_md_base->last = prev;
			else ctx->ft_md_base->last = NULL;
		}
		if(prev != NULL) prev->next = iter->next;
		else{
			if(ctx->ft_md_base->next->next == NULL)ctx->ft_md_base->next = NULL;
			else ctx->ft_md_base->next = ctx->ft_md_base->next->next;
		}
		os_free(to_remove, sizeof(struct ftrace_info));
		// if(ctx->ft_md_base->next == NULL){
		// 	// printk("freeing ftrace_head .. \n");
		// 	os_free(ctx->ft_md_base, sizeof(struct ftrace_head));
		// 	ctx->ft_md_base = NULL;
		// }
	}
	if(action == ENABLE_BACKTRACE){
		// find the function address in the list
		// update the capture_backtrace block
		struct ftrace_info* iter = ctx->ft_md_base->next;
		int flag = 0;
		while(1){
			if(iter == NULL) break;
			if(iter->faddr == faddr){
				flag = 1;
				break;
			}
			iter = iter->next;
		}
		if(flag == 0) return -EINVAL;
		//code for corrupting the first instruciton
		char* fad = (char*)iter->faddr;
		if(*(u8*)(fad) != INV_OPCODE){
			for(int i=0; i<4; i++){
				iter->code_backup[i] = *(u8*)(fad+i);
				((u8*)fad)[i] = INV_OPCODE;
			}
		}

		if(iter->capture_backtrace == 1) return -EINVAL;
		iter->capture_backtrace = 1;
	}
	if(action == DISABLE_BACKTRACE){
		struct ftrace_info* iter = ctx->ft_md_base->next;
		while(iter->faddr != faddr){
			iter = iter->next;
		}
		if(iter == NULL) return -EINVAL;
		if(iter->capture_backtrace == 0) return -EINVAL;
		iter->capture_backtrace = 0;
	}
    return 0;
}

//Fault handler
long handle_ftrace_fault(struct user_regs *regs)
{
	// printk("rdi: %d, rsi: %d, rdx: %d, rcx: %d, r8: %d, r9: %d \n", regs->rdi, regs->rsi, regs->rdx, regs->rcx, regs->r8, regs->r9);
	// printk("return addr %x \n", (u64)*((u64*)regs->entry_rsp));
	// printk("the addr of the func being called: %x\n", regs->entry_rip);
	// u64 ret = (u64)*((u64*)regs->entry_rsp);


	// handle the tracing part here...
	struct exec_context* ctx = get_current_ctx();
	struct ftrace_info* iter = ctx->ft_md_base->next;
	while(iter->faddr != regs->entry_rip){
		iter = iter->next;
	}
		// printk("inside handlr\n"); 
	u64 params[6] = {(u64)iter->faddr, (u64)regs->rdi, (u64)regs->rsi, (u64)regs->rdx, (u64)regs->rcx, (u64)regs->r8};

	int n = iter->num_args;
	u64 bytes_written = 0;
	struct file* filep = ctx->files[iter->fd];
	struct trace_buffer_info* trace_buffer = filep->trace_buffer;
	u64 initial_offset = filep->trace_buffer->write_offset;
	filep->trace_buffer->write_offset += 8;
	filep->trace_buffer->write_offset %= TRACE_BUFFER_MAX_SIZE;
	filep->trace_buffer->alloted_bytes += 8;

	//write to the filep->mem
	for(int i=0; i<n+1; i++){
		if(filep->trace_buffer->alloted_bytes == TRACE_BUFFER_MAX_SIZE){
			// printk("breaked!!??\n");
			break;
		}
		u64 t = params[i];
		// printk("writing this : %x, at the write-offset : %d\n", t, filep->trace_buffer->write_offset);
		((u64*)filep->trace_buffer->mem)[filep->trace_buffer->write_offset/8] = t;
		filep->trace_buffer->write_offset += 8;
		filep->trace_buffer->write_offset %= TRACE_BUFFER_MAX_SIZE;
		filep->trace_buffer->alloted_bytes += 8;
		bytes_written += 8;
	}

	iter = ctx->ft_md_base->next;
	u64 faddr = regs->entry_rip;
	while(iter->faddr != faddr && iter != NULL){
		iter = iter->next;
	}
	// if(iter == NULL) printk("iter became NULL \n");
	if(iter != NULL && iter->capture_backtrace == 1){
		// do the fill backtrace logic
		// printk("is it leaking in??\n");
		u64 iterator = regs->rbp;
		// printk("writing this at backtrace: %x\n", iter->faddr);
		((u64*)filep->trace_buffer->mem)[filep->trace_buffer->write_offset/8] = iter->faddr;	
		filep->trace_buffer->write_offset += 8;
		filep->trace_buffer->write_offset %= TRACE_BUFFER_MAX_SIZE;
		filep->trace_buffer->alloted_bytes += 8;
		bytes_written += 8;
		// printk("writing this at backtrace: %x\n", regs->entry_rsp);
		((u64*)filep->trace_buffer->mem)[filep->trace_buffer->write_offset/8] = *((u64*)regs->entry_rsp);	
		filep->trace_buffer->write_offset += 8;
		filep->trace_buffer->write_offset %= TRACE_BUFFER_MAX_SIZE;
		filep->trace_buffer->alloted_bytes += 8;
		bytes_written += 8;
		while(1){
			// printk("ENDADDR : %x, CURR_ = %x \n", END_ADDR, *((u64*)(iterator+8)));
			if(*((u64*)(iterator+8)) == END_ADDR) break;
			((u64*)filep->trace_buffer->mem)[filep->trace_buffer->write_offset/8] = *((u64*)(iterator+8));	
			filep->trace_buffer->write_offset += 8;
			filep->trace_buffer->write_offset %= TRACE_BUFFER_MAX_SIZE;
			filep->trace_buffer->alloted_bytes += 8;
			bytes_written += 8;
			if(*((u64*)(iterator+8)) != END_ADDR)iterator = *((u64*)iterator);
		};
	}
	// printk("the number of bytes written = %d, initial_offset = %d\n", bytes_written, initial_offset);
	((u64*)filep->trace_buffer->mem)[initial_offset/8] = bytes_written;
	// printk("the value at initial_offset + 8 = %x\n", *(u64*)(filep->trace_buffer->mem + initial_offset + 8));
	regs->entry_rsp -= 8;
	*((u64*)regs->entry_rsp) = regs->rbp;
	regs->rbp = regs->entry_rsp;
	regs->entry_rip += 4;
    return 0;
}


int sys_read_ftrace(struct file *filep, char *buff, u64 count)
{
	// printk("inside read ftrace\n");
	struct exec_context* ctx = get_current_ctx();
	// for(int i=0; i<100; i++){
	// 	printk("just reading : ((u64*)filep->trace_buffer->mem)[%d] : %x\n", filep->trace_buffer->read_offset + i*8, ((u64*)filep->trace_buffer->mem)[filep->trace_buffer->read_offset/8 + i]);
	// }
	int ret = 0, sub_from_ret = 0;
	for(int j=0; j<count; j++){
		// printk("{SYS_READ_FTRACE} count = %d\n", j);
		u64 file_addr = ((u64*)filep->trace_buffer->mem)[filep->trace_buffer->read_offset/8];
		// printk("the file_addr initially: %x\n", file_addr);		
		file_addr = ((u64*)filep->trace_buffer->mem)[filep->trace_buffer->read_offset/8+1];		
		// printk("the file_addr initially: %x\n", file_addr);		
		struct ftrace_info* iter =  ctx->ft_md_base->next;
		while(iter->faddr != file_addr){
			// printk("inside this while loop\n");print_unsigned_long(file_addr); printk("\n");
			iter = iter->next;
		}
		int backtrace_read = iter->capture_backtrace;

		// ---------
		u64 read_count = ((u64*)filep->trace_buffer->mem)[filep->trace_buffer->read_offset/8];
		filep->trace_buffer->read_offset += 8;
		filep->trace_buffer->read_offset %= TRACE_BUFFER_MAX_SIZE;
		filep->trace_buffer->alloted_bytes -= 8;
		// printk("the read_offset = %d, read_count = %d\n", filep->trace_buffer->read_offset, read_count);
		for(int i=0; i<read_count/8; i++){
			// printk("{SYS_READ_FTRACE} i = %d, alloted_bytes = %d\n", i, filep->trace_buffer->alloted_bytes);
			if(filep->trace_buffer->alloted_bytes == 0){
				break;
			}
			((u64*)buff)[ret/8 + i] = ((u64*)filep->trace_buffer->mem)[filep->trace_buffer->read_offset/8];
			// printk("inside for loop i = %d\n", ret/8 + i);
			// printk("value here: %x \n", ((u64*)buff)[ret/8 + i]);
			filep->trace_buffer->read_offset += 8;
			filep->trace_buffer->read_offset %= TRACE_BUFFER_MAX_SIZE;
			filep->trace_buffer->alloted_bytes -= 8;
		}

		ret += read_count;
		// ---------
		// int n = iter->num_args;
		// // printk("the number of arguments : %d, start: %d, end: %d \n", n, (ret-sub_from_ret)/8, (ret-sub_from_ret)/8+n+1);
		// int start = (ret-sub_from_ret)/8, end = ((ret-sub_from_ret)/8+n+1);
		// for(int i=start; i<end; i++){
		// // printk("the number of arguments : %d, start: %d, end: %d \n", i, (ret-sub_from_ret)/8, (ret-sub_from_ret)/8+n+1);
		// 	if(filep->trace_buffer->alloted_bytes == 0){
		// 		break;
		// 	}
		// 	((u64*)buff)[i] = ((u64*)filep->trace_buffer->mem)[filep->trace_buffer->read_offset];
		// 	// printk("inside for loop i = %d\n", i);
		// 	// printk("value here: %x \n", ((u64*)buff)[i]);
		// 	filep->trace_buffer->read_offset += 8;
		// 	filep->trace_buffer->read_offset %= TRACE_BUFFER_MAX_SIZE;
		// 	filep->trace_buffer->alloted_bytes -= 8;
		// 	ret += 8;
		// }
		// if(backtrace_read == 1){
		// 	while(1){
		// 		u64 temp = ((u64*)filep->trace_buffer->mem)[filep->trace_buffer->read_offset];
		// 		// printk("inside backtrace read i = %d\n",filep->trace_buffer->read_offset/8);
		// 		// printk("the value here: %x , END_ADDR = %x \n", temp, END_ADDR);
		// 		if(temp == END_ADDR){
		// 			ret += 8;
		// 			sub_from_ret += 8;
		// 			filep->trace_buffer->read_offset += 8;
		// 			filep->trace_buffer->read_offset %= TRACE_BUFFER_MAX_SIZE;
		// 			filep->trace_buffer->alloted_bytes -= 8;
		// 			break;
		// 		}
		// 		((u64*)buff)[(ret-sub_from_ret)/8] = temp;
		// 		filep->trace_buffer->read_offset += 8;
		// 		filep->trace_buffer->read_offset %= TRACE_BUFFER_MAX_SIZE;
		// 		filep->trace_buffer->alloted_bytes -= 8;
		// 		ret += 8;

		// 	}
		// }
		// printk("the alloted bytes left are: %d \n", filep->trace_buffer->alloted_bytes);
		if(filep->trace_buffer->alloted_bytes <= 0){
			break;
		}
	}
	// printk("ret - sub_from_ret %d \n", ret-sub_from_ret);
	return ret-sub_from_ret;
}

